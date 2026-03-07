# ksmbd-torture: Edge Case & Regression Test Catalog

This document catalogs every edge case found in the ksmbd source code that
must be tested, plus all bugs previously fixed (from the project MEMORY.md).
Edge cases are derived from exhaustive source analysis of all SMB2 command
handlers, negotiate/session setup paths, and server core processing logic.

**Total edge cases: 501**
**Total regression tests: 40**
**Grand total: 541 test entries**

---

## Source-Derived Edge Cases

### CREATE Edge Cases (112 cases)

#### Create Disposition Edge Cases

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-001 | FILE_OPEN on non-existent file returns error | smb2_create.c:1926 | `smbtorture smb2.create.open` | STATUS_OBJECT_NAME_NOT_FOUND | P1 |
| EDGE-002 | FILE_CREATE on existing file returns collision | smb2_create.c:1926 | `smbtorture smb2.create.gentest` | STATUS_OBJECT_NAME_COLLISION | P1 |
| EDGE-003 | FILE_SUPERSEDE on existing file truncates and removes EAs/SD | smb2_create.c:645-689 | Custom: create file with EAs, supersede, verify EAs gone | File truncated, EAs/SD removed | P1 |
| EDGE-004 | FILE_OVERWRITE on non-existent file fails | smb2_create.c:120-123 | `smbclient` open with O_TRUNC on missing file | STATUS_OBJECT_NAME_NOT_FOUND | P1 |
| EDGE-005 | FILE_OVERWRITE_IF creates if not present, truncates if present | smb2_create.c:117-118 | `smbtorture smb2.create.gentest --target=win7` | FILE_CREATED or FILE_OVERWRITTEN | P1 |
| EDGE-006 | FILE_OPEN_IF opens existing or creates new | smb2_create.c:116 | `smbtorture smb2.create.gentest` | FILE_OPENED or FILE_CREATED | P1 |
| EDGE-007 | Disposition > FILE_OVERWRITE_IF (value 5) rejected | smb2_create.c:1616-1622 | Custom: send raw SMB2 with disposition=6 | STATUS_INVALID_PARAMETER | P0 |

#### Create Options Validation

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-008 | FILE_DIRECTORY_FILE + FILE_NON_DIRECTORY_FILE conflict | smb2_create.c:1607-1609 | Custom client | STATUS_INVALID_PARAMETER | P1 |
| EDGE-009 | FILE_DIRECTORY_FILE + ATTR_TEMPORARY conflict | smb2_create.c:1638-1642 | Custom client | STATUS_INVALID_PARAMETER | P1 |
| EDGE-010 | FILE_SEQUENTIAL_ONLY + FILE_RANDOM_ACCESS: sequential stripped | smb2_create.c:1584-1586 | Debug log check | Sequential flag cleared silently | P2 |
| EDGE-011 | CREATE_TREE_CONNECTION option rejected | smb2_create.c:1588-1591 | Custom client | STATUS_NOT_SUPPORTED | P1 |
| EDGE-012 | FILE_RESERVE_OPFILTER rejected | smb2_create.c:1593-1596 | Custom client | STATUS_NOT_SUPPORTED | P1 |
| EDGE-013 | FILE_OPEN_BY_FILE_ID resolves to path then opens normally | smb2_create.c:1370-1380, 1224-1268 | Custom client with file ID | File opened by resolved path | P2 |

#### Filename Parsing Edge Cases

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-014 | Empty name (NameLength=0) opens share root | smb2_create.c:1490-1496 | `smbclient` open "" | Share root directory opened | P1 |
| EDGE-015 | Odd NameLength (not UTF-16LE aligned) rejected | smb2_create.c:1359-1361 | Custom: send NameLength=5 | STATUS_INVALID_PARAMETER | P0 |
| EDGE-016 | NameOffset+NameLength exceeds request buffer | smb2_create.c:1364-1368 | Custom: overflow offset | STATUS_INVALID_PARAMETER | P0 |
| EDGE-017 | Path with ".." (dot-dot traversal) rejected | smb2_create.c:1478-1482 | `smbclient` open "../etc/passwd" | STATUS_OBJECT_PATH_SYNTAX_BAD | P0 |
| EDGE-018 | Vetoed filename rejected | smb2_create.c:1484-1489 | Configure veto files, try open | STATUS_OBJECT_NAME_INVALID | P1 |
| EDGE-019 | DesiredAccess has no valid bits set | smb2_create.c:1624-1629 | Custom: DesiredAccess=0x80000000 | STATUS_ACCESS_DENIED | P0 |
| EDGE-020 | DesiredAccess includes SYNCHRONIZE (bit 20) | smb2_create.c:1624 | `smbtorture smb2.create.gentest --target=win7` | Accepted (mask = 0xF21F01FF) | P1 |
| EDGE-021 | FileAttributes with no valid bits set | smb2_create.c:1631-1636 | Custom: FileAttributes=0x10000 | STATUS_INVALID_PARAMETER | P1 |
| EDGE-022 | $Extend\\$Quota fake file mapped to share root | smb2_create.c:1402-1414 | Custom: open "$Extend\\$Quota:$Q:$INDEX_ALLOCATION" | HIDDEN+SYSTEM+DIR attrs, zero timestamps | P2 |

#### Stream Name Handling

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-023 | Named stream with FILE_DIRECTORY_FILE on data stream | smb2_create.c:1849-1853 | `smbtorture smb2.streams.dir` | STATUS_NOT_A_DIRECTORY | P1 |
| EDGE-024 | Default stream (::$DATA) on directory without FILE_DIRECTORY_FILE | smb2_create.c:1917-1923 | `smbtorture smb2.streams.dir` | STATUS_FILE_IS_A_DIRECTORY | P1 |
| EDGE-025 | Streams disabled on share, name contains colon | smb2_create.c:1418-1421 | Disable streams flag, open "file:stream" | STATUS_OBJECT_NAME_NOT_FOUND | P1 |

#### Durable Handle Reconnect

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-026 | DH2C with mismatched CreateGuid fails | smb2_create.c:1003-1008 | `smbtorture smb2.durable-v2-open.reopen-mismatch` | STATUS_OBJECT_NAME_NOT_FOUND | P1 |
| EDGE-027 | DH2C with persistent flag on non-persistent handle rejected | smb2_create.c:1516-1537 | Custom client | STATUS_OBJECT_NAME_NOT_FOUND | P1 |
| EDGE-028 | DHnC v1 reconnect (no CreateGuid validation) | smb2_create.c:1042-1062 | `smbtorture smb2.durable-open.reopen1` | Handle reconnected | P1 |
| EDGE-029 | DH2Q with replay flag on existing GUID returns existing handle | smb2_create.c:1085-1096 | `smbtorture smb2.durable-v2-open.replay` | Same FID returned | P1 |
| EDGE-030 | Mutual exclusion: DH2C + DHnQ conflict | smb2_create.c:968-972 | Custom client | STATUS_INVALID_PARAMETER | P1 |
| EDGE-031 | Mutual exclusion: DHnC + DH2Q conflict | smb2_create.c:1029-1033 | Custom client | STATUS_INVALID_PARAMETER | P1 |
| EDGE-032 | DH2Q requires batch oplock or handle lease | smb2_create.c:1099-1108 | Open with RWH lease, expect durable | Durable context in response | P1 |

#### VSS/Snapshot Edge Cases

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-033 | TWrp context with valid snapshot timestamp resolves path | smb2_create.c:1693-1749 | Configure .snapshots, TWrp open | Snapshot file version opened | P2 |
| EDGE-034 | TWrp context with invalid/missing snapshot fails | smb2_create.c:1732-1738 | TWrp with bogus timestamp | STATUS_OBJECT_NAME_NOT_FOUND | P2 |
| EDGE-035 | TWrp DataLength < sizeof(__le64) rejected | smb2_create.c:1696-1701 | Custom: short TWrp data | STATUS_INVALID_PARAMETER | P1 |

#### Path Traversal and Security

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-036 | Symlink without FILE_OPEN_REPARSE_POINT rejected | smb2_create.c:1821-1827 | Create symlink, open without flag | STATUS_ACCESS_DENIED | P0 |
| EDGE-037 | FILE_OPEN_REPARSE_POINT allows opening symlink itself | smb2_create.c:1781-1782, 1814-1828 | Create symlink, open with flag | Symlink dentry opened | P1 |
| EDGE-038 | Post-open TOCTOU check: path escapes share root | smb2_create.c:2145-2151 | Race condition: symlink swap | STATUS_ACCESS_DENIED | P0 |
| EDGE-039 | Parent DACL deny check for file creation | smb2_create.c:2015-2053 | Set deny ACE on parent dir, create child | STATUS_ACCESS_DENIED | P1 |
| EDGE-040 | Parent DACL deny check for subdirectory creation | smb2_create.c:2023-2024 | Set deny ACE (ADD_SUBDIR), create subdir | STATUS_ACCESS_DENIED | P1 |

#### ImpersonationLevel Validation

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-041 | ImpersonationLevel > IL_DELEGATE rejected | smb2_create.c:1570-1576 | Custom: ImpersonationLevel=5 | STATUS_BAD_IMPERSONATION_LEVEL | P1 |

#### File Presence Checks

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-042 | FILE_NON_DIRECTORY_FILE on directory returns error | smb2_create.c:1895-1901 | Open dir with NON_DIRECTORY_FILE | STATUS_FILE_IS_A_DIRECTORY | P1 |
| EDGE-043 | FILE_DIRECTORY_FILE on non-directory (not FILE_CREATE) | smb2_create.c:1904-1910 | Open file with DIRECTORY_FILE | STATUS_NOT_A_DIRECTORY | P1 |
| EDGE-044 | File not found and not O_CREAT disposition | smb2_create.c:1841-1846 | FILE_OPEN on non-existent file | STATUS_OBJECT_NAME_NOT_FOUND | P1 |
| EDGE-045 | Parent path not found during create | smb2_create.c:2060-2063 | Create in non-existent subdirectory | STATUS_OBJECT_PATH_NOT_FOUND | P1 |

#### DACL and Permission Checks

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-046 | smb_check_perm_dacl returns -EACCES, hide-on-access-denied | smb2_create.c:1942-1957 | Empty DACL (no ACEs), open file | STATUS_OBJECT_NAME_NOT_FOUND (file hidden) | P1 |
| EDGE-047 | smb_check_perm_dacl with FILE_READ_ATTRIBUTES grant | smb2_create.c:1953-1956 | ACE grants only READ_ATTRIBUTES | STATUS_ACCESS_DENIED (file visible) | P1 |
| EDGE-048 | MAXIMUM_ALLOWED resolves to computed access rights | smb2_create.c:1974-1992 | Open with FILE_MAXIMAL_ACCESS | Resolved daccess in response | P1 |
| EDGE-049 | Read-only share rejects O_CREAT/O_TRUNC | smb2_create.c:2000-2007 | Write to read-only share | STATUS_ACCESS_DENIED | P1 |
| EDGE-050 | inode_permission check skipped when DACL already validated | smb2_create.c:2088 | MAXIMUM_ALLOWED with DACL xattr present | No double permission check | P2 |

#### OVERWRITE Attribute Mismatch

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-051 | OVERWRITE on HIDDEN file without HIDDEN in request | smb2_create.c:1866-1893 | Set HIDDEN attr, OVERWRITE without HIDDEN | STATUS_ACCESS_DENIED | P1 |
| EDGE-052 | OVERWRITE on SYSTEM file without SYSTEM in request | smb2_create.c:1884-1885 | Set SYSTEM attr, OVERWRITE without SYSTEM | STATUS_ACCESS_DENIED | P1 |

#### Delete-on-Close Constraints

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-053 | DELETE_ON_CLOSE without FILE_DELETE in GrantedAccess | smb2_create.c:2477-2480 | Open with DOC but no DELETE access | STATUS_ACCESS_DENIED | P0 |
| EDGE-054 | DELETE_ON_CLOSE on READONLY file | smb2_create.c:2486-2492 | Mark file read-only, DOC open | STATUS_CANNOT_DELETE | P0 |
| EDGE-055 | DELETE_ON_CLOSE with OVERWRITE_IF on existing file | smb2_create.c:1796-1803 | DOC + OVERWRITE_IF on existing | STATUS_ACCESS_DENIED | P1 |
| EDGE-056 | DELETE_ON_CLOSE with OPEN_IF on existing file | smb2_create.c:1797 | DOC + OPEN_IF on existing | STATUS_ACCESS_DENIED | P1 |
| EDGE-057 | DELETE_ON_CLOSE on read-only share | smb2_create.c:1805-1813 | DOC on read-only share | STATUS_ACCESS_DENIED | P1 |

#### Pending Delete Checks

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-058 | Open on file with pending delete | smb2_create.c:2339-2344 | First handle sets DOC, second handle opens | STATUS_DELETE_PENDING | P1 |
| EDGE-059 | Open on file with pending delete but only handle | smb2_create.c:2340 | DOC, close, reopen before unlink | Pending cleared if only opener | P2 |
| EDGE-060 | Create in parent with pending delete | smb2_create.c:2128-2134 | Set parent delete-pending, create child | STATUS_DELETE_PENDING | P1 |

#### EA and Create Context Handling

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-061 | EA buffer with FILE_NO_EA_KNOWLEDGE flag | smb2_create.c:1664-1668 | EA context + NO_EA_KNOWLEDGE | STATUS_ACCESS_DENIED | P1 |
| EDGE-062 | EA buffer DataLength < sizeof(smb2_ea_info) | smb2_create.c:2074-2077 | Custom: short EA buffer | STATUS_INVALID_PARAMETER | P1 |
| EDGE-063 | EA name exceeds XATTR_NAME_MAX limit | smb2_create.c:376-379 | Custom: EA name > 255 chars | STATUS_INVALID_PARAMETER | P1 |
| EDGE-064 | EA setting "security.NTACL" directly blocked | smb2_create.c:389-393 | Custom: set EA named "NTACL" | STATUS_ACCESS_DENIED | P0 |
| EDGE-065 | Create context with misaligned Next offset | smb2_create.c:1167 | Custom: Next not 8-byte aligned | STATUS_INVALID_PARAMETER | P1 |
| EDGE-066 | Create context NameLength < 4 rejected | smb2_create.c:1170 | Custom: NameLength=2 | STATUS_INVALID_PARAMETER | P1 |
| EDGE-067 | Allocation size context sets initial allocation | smb2_create.c:2504-2535 | Open with AllocationSize context | vfs_fallocate called | P2 |

#### Oplock/Lease in CREATE

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-068 | FILE_COMPLETE_IF_OPLOCKED with existing oplock | smb2_create.c:2398-2430 | Hold batch oplock, open with flag | STATUS_OPLOCK_BREAK_IN_PROGRESS | P1 |
| EDGE-069 | FILE_OPEN_REQUIRING_OPLOCK fails when oplock downgraded | smb2_create.c:2448-2467 | Conflicting open prevents batch | STATUS_OPLOCK_NOT_GRANTED | P1 |
| EDGE-070 | Lease request on directory strips WRITE caching | smb2_create.c:2365-2367 | Open dir with RWH lease | RH lease only (no W) | P1 |
| EDGE-071 | Parent lease break notification sent | smb2_create.c:2375 | Hold parent key lease, create child | Parent lease break | P2 |
| EDGE-072 | Read-only open with batch/exclusive request downgraded to Level II | smb2_create.c:2384-2387 | O_RDONLY with batch oplock req | Level II granted | P2 |
| EDGE-073 | Share mode violation on non-directory without oplocks | smb2_create.c:2359-2361 | Exclusive open, second open | STATUS_SHARING_VIOLATION | P1 |
| EDGE-074 | Oplock break before truncate on OVERWRITE | smb2_create.c:2349-2353 | Hold oplock, OVERWRITE same file | Break sent before truncate | P1 |

#### IPC Pipe Create

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-075 | Pipe create with NameOffset+NameLength > request size | smb2_create.c:271-276 | Custom: overflow in pipe name | STATUS_INVALID_PARAMETER | P0 |
| EDGE-076 | Pipe create fails to open RPC pipe | smb2_create.c:287-291 | Open non-existent pipe name | Error status | P1 |
| EDGE-077 | Pipe create name allocation failure | smb2_create.c:280-284 | OOM simulation | STATUS_NO_MEMORY | P2 |

#### Security Descriptor in Create

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-078 | SD buffer context sets ACL on new file | smb2_create.c:776-802 | Create with SD buffer context | ACL applied to file | P1 |
| EDGE-079 | SD buffer with short DataLength rejected | smb2_create.c:796-799 | Custom: truncated SD buffer | STATUS_INVALID_PARAMETER | P1 |
| EDGE-080 | No SD buffer: inherit DACL from parent | smb2_create.c:2214-2219 | Create file in ACL-xattr-enabled share | Parent DACL inherited | P2 |
| EDGE-081 | No SD buffer, no parent DACL: POSIX ACL fallback | smb2_create.c:2222-2229 | Create file without parent xattr | POSIX ACL set | P2 |

#### Durable Handle Timeout

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-082 | DH2Q timeout capped at DURABLE_HANDLE_MAX_TIMEOUT | smb2_create.c:2652-2655 | Request 999999ms timeout | Capped to max | P2 |
| EDGE-083 | DH2Q default timeout when client sends 0 | smb2_create.c:2657-2658 | Request timeout=0 | 60000ms default | P2 |
| EDGE-084 | DHnQ v1 gets 16s default timeout | smb2_create.c:2667 | DHnQ request | 16000ms timeout | P2 |

#### Persistent Handle

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-085 | Persistent handle requires CA share flag | smb2_create.c:2643-2645 | DH2Q with persistent on non-CA share | Non-persistent durable | P2 |
| EDGE-086 | Persistent handle save stub emits WARN_ONCE | smb2_create.c:901-907 | DH2Q with persistent on CA share | ksmbd_ph_save WARN in dmesg | P2 |

#### POSIX Create Context

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-087 | POSIX create context DataLength too short | smb2_create.c:1344-1349 | Custom: short POSIX context | STATUS_INVALID_PARAMETER | P1 |
| EDGE-088 | POSIX mode applied to new file | smb2_create.c:2056-2058 | Create with POSIX mode=0644 | File created with 0644 | P2 |
| EDGE-089 | POSIX open bypasses delete-pending check | smb2_create.c:2339 | POSIX open on DOC file | Open succeeds (POSIX unlink) | P2 |

#### Response Context Assembly

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-090 | Lease context response overflow check | smb2_create.c:2729-2733 | Negotiate many contexts to fill buffer | No buffer overflow | P0 |
| EDGE-091 | Maximal access context response | smb2_create.c:2749-2779 | Open with MxAc context | MxAc response context present | P2 |
| EDGE-092 | Query on disk ID context response | smb2_create.c:2781-2803 | Open with QFid context | Disk ID context in response | P2 |
| EDGE-093 | Multiple create contexts chained with correct Next offsets | smb2_create.c:2776, 2800 | Open with lease+MxAc+QFid | All contexts with valid Next | P1 |

#### Error Mapping

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-094 | -EINVAL maps to STATUS_INVALID_PARAMETER | smb2_create.c:2912 | Various invalid parameters | Correct mapping | P2 |
| EDGE-095 | -EOPNOTSUPP maps to STATUS_NOT_SUPPORTED | smb2_create.c:2914 | Unsupported operation | Correct mapping | P2 |
| EDGE-096 | -EACCES maps to STATUS_ACCESS_DENIED | smb2_create.c:2918 | Permission denied | Correct mapping | P1 |
| EDGE-097 | -ENOENT maps to STATUS_OBJECT_NAME_INVALID | smb2_create.c:2920 | Name not found | Correct mapping | P1 |
| EDGE-098 | -EPERM maps to STATUS_SHARING_VIOLATION | smb2_create.c:2922 | Sharing conflict | Correct mapping | P1 |
| EDGE-099 | -EBUSY maps to STATUS_DELETE_PENDING | smb2_create.c:2924 | Delete pending | Correct mapping | P1 |
| EDGE-100 | -EBADF maps to STATUS_OBJECT_NAME_NOT_FOUND | smb2_create.c:2926 | Bad file descriptor | Correct mapping | P1 |
| EDGE-101 | -ENOEXEC maps to STATUS_DUPLICATE_OBJECTID | smb2_create.c:2928 | Duplicate object | Correct mapping | P2 |
| EDGE-102 | -ENXIO maps to STATUS_NO_SUCH_DEVICE | smb2_create.c:2930 | No device | Correct mapping | P2 |
| EDGE-103 | -EEXIST maps to STATUS_OBJECT_NAME_COLLISION | smb2_create.c:2932 | Name collision | Correct mapping | P1 |
| EDGE-104 | -EMFILE maps to STATUS_INSUFFICIENT_RESOURCES | smb2_create.c:2934 | Too many files | Correct mapping | P2 |
| EDGE-105 | -ENOKEY maps to STATUS_PRIVILEGE_NOT_HELD | smb2_create.c:2936 | Privilege needed | Correct mapping | P2 |
| EDGE-106 | Pre-set status (e.g. STATUS_CANNOT_DELETE) preserved | smb2_create.c:2910 | DOC on readonly file | STATUS_CANNOT_DELETE not overwritten | P0 |

#### Registered Create Context Dispatch

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-107 | APP_INSTANCE_ID processed after other contexts | smb2_create.c:1207-1222 | Open with APP_INSTANCE_ID + other contexts | Order preserved | P2 |
| EDGE-108 | Unknown create context name silently ignored | smb2_create.c:1187-1188 | Send unknown context name | Ignored, open succeeds | P2 |
| EDGE-109 | Create context handler returns error | smb2_create.c:1197-1198 | Handler error path | Error propagated | P2 |

#### Miscellaneous CREATE

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-110 | First compound with RELATED flag rejected | smb2_create.c:1323-1329 | Compound: first request has RELATED | STATUS_INVALID_PARAMETER | P1 |
| EDGE-111 | Fruit AAPL create context negotiation | smb2_create.c:2546-2608 | macOS client with AAPL context | Fruit capability negotiated | P2 |
| EDGE-112 | SUPERSEDE sets file_info = FILE_SUPERSEDED | smb2_create.c:2160-2161 | SUPERSEDE on existing file | CreateAction = FILE_SUPERSEDED | P1 |

---

### LOCK Edge Cases (69 cases)

#### Cancel Logic

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-113 | Async cancel by AsyncId | smb2_lock.c:83-122 | `smbtorture smb2.lock.cancel` | Lock cancelled, STATUS_CANCELLED | P1 |
| EDGE-114 | Async cancel on compound-spawned work (no request_buf) | smb2_lock.c:91-98 | Compound with CHANGE_NOTIFY + CANCEL | Notify cancelled | P1 |
| EDGE-115 | Sync cancel by MessageId | smb2_lock.c:127-149 | `smbtorture smb2.lock.cancel` | Lock cancelled | P1 |
| EDGE-116 | Sync cancel fallback to async list by MessageId | smb2_lock.c:163-187 | Cancel before interim received | Found in async list | P1 |
| EDGE-117 | Sync cancel with MessageId=0 matches by SessionId | smb2_lock.c:195-220 | Cancel with mid=0 | Matched by SessionId | P1 |
| EDGE-118 | Cancel invokes cancel_fn callback | smb2_lock.c:123-124 | Lock cancel triggers smb2_remove_blocked_lock | POSIX lock unblocked | P1 |
| EDGE-119 | Cancel clears cancel_fn/cancel_argv to prevent double-free | smb2_lock.c:117-119 | Race: cancel + close | No double-free | P0 |
| EDGE-120 | Cancel on self (iter == work) skipped | smb2_lock.c:134 | Self-referencing cancel | Self skipped | P2 |
| EDGE-121 | Cancel callback frees argv | smb2_lock.c:125 | Cancel callback invocation | argv freed after callback | P2 |
| EDGE-122 | Cancel sends STATUS_CANCELLED response | smb2_lock.c:950-955 | `smbtorture smb2.lock.cancel` | STATUS_CANCELLED in final response | P1 |

#### Lock Flags Validation

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-123 | Unknown flag bits rejected | smb2_lock.c:672-675 | Custom: Flags=0xFF | STATUS_INVALID_PARAMETER | P1 |
| EDGE-124 | Mixed lock+unlock in same request rejected | smb2_lock.c:677-683 | EXCLUSIVE first, then UNLOCK | STATUS_INVALID_PARAMETER | P1 |
| EDGE-125 | Mixed unlock+lock in same request rejected | smb2_lock.c:679-680 | UNLOCK first, then EXCLUSIVE | STATUS_INVALID_PARAMETER | P1 |
| EDGE-126 | SHARED lock flag sets F_RDLCK | smb2_lock.c:306-316 | `smbtorture smb2.lock.shared` | Shared lock acquired | P1 |
| EDGE-127 | EXCLUSIVE lock flag sets F_WRLCK | smb2_lock.c:317-327 | `smbtorture smb2.lock.exclusive` | Exclusive lock acquired | P1 |
| EDGE-128 | SHARED + FAIL_IMMEDIATELY is non-blocking read lock | smb2_lock.c:328-337 | Try-lock on contended range | STATUS_LOCK_NOT_GRANTED immediately | P1 |
| EDGE-129 | EXCLUSIVE + FAIL_IMMEDIATELY is non-blocking write lock | smb2_lock.c:338-347 | Try-lock on contended range | STATUS_LOCK_NOT_GRANTED immediately | P1 |
| EDGE-130 | UNLOCK flag sets F_UNLCK | smb2_lock.c:348-356 | `smbtorture smb2.lock.unlock` | Lock released | P1 |
| EDGE-131 | Invalid flag combination returns -EINVAL from smb2_set_flock_flags | smb2_lock.c:302, 667-669 | Custom: Flags=SHARED|EXCLUSIVE | STATUS_INVALID_PARAMETER | P1 |

#### Lock Sequence Replay

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-132 | Lock sequence index 0 skips validation | smb2_lock.c:442-443 | Durable handle, LockSeqIdx=0 | Lock processed normally | P1 |
| EDGE-133 | Lock sequence index > 64 skips validation | smb2_lock.c:446-447 | Durable handle, LockSeqIdx=65 | Lock processed normally | P1 |
| EDGE-134 | Lock sequence replay on resilient handle returns OK | smb2_lock.c:454-458 | Same seq_num on same index | STATUS_OK immediately | P1 |
| EDGE-135 | Lock sequence different seq_num invalidates entry | smb2_lock.c:461-462 | Different seq_num on same index | Entry invalidated, lock processed | P1 |
| EDGE-136 | Lock sequence stored only after successful lock | smb2_lock.c:988 | Lock success stores sequence | Sequence stored in fp->lock_seq | P1 |
| EDGE-137 | Lock sequence not stored on lock failure | smb2_lock.c:988 | Lock conflict (no store) | Sequence not stored | P1 |
| EDGE-138 | Non-durable handle skips lock sequence check | smb2_lock.c:450-451 | Regular handle with LockSeqIdx=1 | Validation skipped | P2 |
| EDGE-139 | Lock sequence uses correct bit extraction (low 4 bits / upper 28 bits) | smb2_lock.c:438-439 | Various LockSequenceNumber values | Correct seq_num and seq_idx | P1 |
| EDGE-140 | Lock sequence 0xFF sentinel means entry not valid | smb2_lock.c:454 | Fresh handle, first lock at index | Entry transitions from 0xFF | P2 |

#### Range Validation

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-141 | Lock count = 0 rejected | smb2_lock.c:551 | Custom: LockCount=0 | STATUS_INVALID_PARAMETER | P1 |
| EDGE-142 | Lock count > KSMBD_MAX_LOCK_COUNT rejected | smb2_lock.c:551 | Custom: LockCount=65536 | STATUS_INVALID_PARAMETER | P0 |
| EDGE-143 | Lock element array exceeds request buffer | smb2_lock.c:558-573 | Custom: overflow lock array | STATUS_INVALID_PARAMETER | P0 |
| EDGE-144 | Offset+Length wraps to non-zero (overflow) | smb2_lock.c:596-603 | offset=~0, length=2 | STATUS_INVALID_LOCK_RANGE | P0 |
| EDGE-145 | Offset+Length wraps to exactly zero is valid | smb2_lock.c:597 | offset=~0, length=1 | Lock accepted | P1 |
| EDGE-146 | Zero-length lock range skips VFS call | smb2_lock.c:861-873 | Lock with Length=0 | ksmbd list only, STATUS_OK | P1 |
| EDGE-147 | Lock start > OFFSET_MAX clamped, VFS call skipped | smb2_lock.c:884-887 | Lock at offset 2^63+1 | VFS skipped, ksmbd tracks | P1 |
| EDGE-148 | Lock length clamped to OFFSET_MAX - start | smb2_lock.c:615-616 | Large length clamped | Clamped flock range | P2 |
| EDGE-149 | POSIX fl_end inclusive (start + length - 1) | smb2_lock.c:623-624 | Lock at offset=0, length=10 | fl_end = 9 | P1 |
| EDGE-150 | fl_end < fl_start check after clamping | smb2_lock.c:628-635 | Edge case after clamping | STATUS_INVALID_LOCK_RANGE | P2 |

#### Conflict Detection

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-151 | Conflict within same request (two locks in lock_list) | smb2_lock.c:638-654 | Request with overlapping lock+lock | STATUS_INVALID_PARAMETER | P1 |
| EDGE-152 | Same-handle blocking exclusive lock conflict | smb2_lock.c:697-740 | Hold shared, request exclusive on same handle | STATUS_LOCK_NOT_GRANTED | P1 |
| EDGE-153 | Zero-byte lock vs non-zero overlap (zero inside range) | smb2_lock.c:800-808 | Zero lock inside non-zero range | STATUS_LOCK_NOT_GRANTED | P1 |
| EDGE-154 | Non-zero lock vs zero-byte overlap (non-zero covers zero) | smb2_lock.c:810-818 | Non-zero range covers zero lock | STATUS_LOCK_NOT_GRANTED | P1 |
| EDGE-155 | Exclusive range overlap with inclusive end comparison | smb2_lock.c:827-840 | Adjacent non-overlapping ranges | No conflict (STATUS_OK) | P1 |
| EDGE-156 | Wrap-around overlap with end=0 (means 2^64) | smb2_lock.c:828-829 | Lock to 2^64, check overlap | Correct: cmp_last = ~0ULL | P1 |
| EDGE-157 | Shared-same-file lock does not conflict with shared | smb2_lock.c:792-793 | Two shared locks on same file | Both succeed | P1 |
| EDGE-158 | Shared-different-file lock conflicts with exclusive | smb2_lock.c:795-796 | Shared on file A, exclusive on file B (same inode) | Conflict detected | P1 |
| EDGE-159 | Unlock on non-existent lock range | smb2_lock.c:847-855 | Unlock range never locked | STATUS_RANGE_NOT_LOCKED | P1 |
| EDGE-160 | Unlock exact range match removes from list | smb2_lock.c:771-783 | Lock then unlock exact range | Lock removed | P1 |

#### Async Lock Lifecycle

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-161 | Blocking lock sends STATUS_PENDING interim | smb2_lock.c:927 | `smbtorture smb2.lock.async` | STATUS_PENDING received | P1 |
| EDGE-162 | Blocking lock wait periodic wakeup checks connection alive | smb2_lock.c:279-285 | Disconnect during blocking lock | Lock cancelled | P1 |
| EDGE-163 | Blocking lock wait checks work state != ACTIVE | smb2_lock.c:279-280 | Cancel during blocking lock | Lock cancelled | P1 |
| EDGE-164 | Lock granted after wait: async released, lock retried | smb2_lock.c:964-966 | Holder releases, waiter proceeds | Lock acquired | P1 |
| EDGE-165 | Cancelled work gets STATUS_CANCELLED response | smb2_lock.c:939-955 | Cancel pending lock | STATUS_CANCELLED final response | P1 |
| EDGE-166 | Failed rollback: all acquired locks rolled back | smb2_lock.c:1001-1038 | Lock 3 of 5 fails, first 2 rolled back | All locks released | P1 |
| EDGE-167 | Blocked work added to fp->blocked_works list | smb2_lock.c:923-925 | Blocking lock setup | Work in blocked_works | P2 |
| EDGE-168 | setup_async_work failure handling | smb2_lock.c:918-921 | OOM during async setup | STATUS_INSUFFICIENT_RESOURCES | P2 |
| EDGE-169 | Oplock break on successful multi-lock when op_count > 1 | smb2_lock.c:984-985 | Multiple oplock holders + lock | Oplock break sent | P2 |

#### Channel Sequence in Lock

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-170 | Stale ChannelSequence rejected | smb2_lock.c:540-543 | Send lock with old channel_sequence | STATUS_FILE_NOT_AVAILABLE | P1 |

#### File Lookup

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-171 | Invalid FID returns error | smb2_lock.c:517-522 | Lock with invalid VolatileFileId | STATUS_FILE_CLOSED | P1 |

---

### READ/WRITE Edge Cases (92 cases)

#### Pipe Operations

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-172 | Read pipe with data available truncated to Length | smb2_read_write.c:247-251 | Read pipe with Length < available | STATUS_BUFFER_OVERFLOW + partial data | P1 |
| EDGE-173 | Read pipe with no data goes async (STATUS_PENDING) | smb2_read_write.c:269-278 | Read empty pipe | STATUS_PENDING interim | P1 |
| EDGE-174 | Read pipe zero-length request with data goes async | smb2_read_write.c:230-237 | Read pipe with Length=0, data present | STATUS_PENDING | P2 |
| EDGE-175 | Read pipe ENOTIMPLEMENTED goes async | smb2_read_write.c:207-211 | Read unimplemented pipe | STATUS_PENDING (no data) | P2 |
| EDGE-176 | Read pipe cancel sends STATUS_CANCELLED | smb2_read_write.c:69-123 | Cancel pending pipe read | STATUS_CANCELLED | P1 |
| EDGE-177 | Read pipe cancel with NULL argv handled | smb2_read_write.c:78-79 | Race: cancel after complete | No crash | P0 |
| EDGE-178 | Write pipe success returns bytes written | smb2_read_write.c:731-747 | Write to pipe | DataLength = length | P1 |
| EDGE-179 | Write pipe failure returns STATUS_PIPE_DISCONNECTED | smb2_read_write.c:716-727 | Write to broken pipe | STATUS_PIPE_DISCONNECTED | P1 |
| EDGE-180 | Write pipe DataOffset+Length overflow check | smb2_read_write.c:697-704 | Custom: overflow data bounds | STATUS_INVALID_PARAMETER | P0 |
| EDGE-181 | Write pipe ENOTIMPLEMENTED treated as success | smb2_read_write.c:711-715 | Write to unimplemented pipe | Success with DataLength | P2 |

#### RDMA Channel

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-182 | SMB30 + RDMA_V1 requires exact RDMA_V1 channel | smb2_read_write.c:311-312 | SMB 3.0 with RDMA_V1 channel | RDMA accepted | P2 |
| EDGE-183 | SMB30 + non-RDMA_V1 channel rejected | smb2_read_write.c:311-312 | SMB 3.0 with RDMA_V1_INVALIDATE | STATUS_INVALID_PARAMETER | P2 |
| EDGE-184 | Channel info offset before Buffer field rejected | smb2_read_write.c:363-366 | Custom: ch_offset < Buffer | STATUS_INVALID_PARAMETER | P0 |
| EDGE-185 | Channel info offset+length exceeds request | smb2_read_write.c:365-366 | Custom: overflow channel info | STATUS_INVALID_PARAMETER | P0 |
| EDGE-186 | Zero channel descriptor count rejected | smb2_read_write.c:323-324 | Custom: ch_count=0 | STATUS_INVALID_PARAMETER | P1 |
| EDGE-187 | RDMA_V1_INVALIDATE stores remote key | smb2_read_write.c:327-349 | RDMA_V1_INVALIDATE with token | Token stored for invalidation | P2 |
| EDGE-188 | RDMA_V1_INVALIDATE with multi-descriptor warns | smb2_read_write.c:346-348 | Custom: 2 descriptors | Rate-limited warning | P2 |
| EDGE-189 | RDMA write with Length=0 succeeds (zero-length valid) | smb2_read_write.c:771-773 | RDMA write with length=0 | Zero bytes written, success | P2 |
| EDGE-190 | Read RDMA channel writes data to client descriptor | smb2_read_write.c:354-376 | RDMA read triggers ksmbd_conn_rdma_write | Data transferred via RDMA | P2 |
| EDGE-191 | Write RDMA: Length and DataOffset must be 0 | smb2_read_write.c:864 | RDMA write with non-zero Length | STATUS_INVALID_PARAMETER | P1 |

#### Read Boundary Conditions

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-192 | Read offset < 0 (after loff_t cast) rejected | smb2_read_write.c:465-468 | Custom: negative offset | STATUS_INVALID_PARAMETER | P0 |
| EDGE-193 | Read offset > MAX_LFS_FILESIZE rejected | smb2_read_write.c:465 | Custom: huge offset | STATUS_INVALID_PARAMETER | P0 |
| EDGE-194 | Read offset+length overflow (wraps past MAX_LFS_FILESIZE) | smb2_read_write.c:480-483 | offset=MAX_LFS_FILESIZE, length=1 | STATUS_INVALID_PARAMETER | P0 |
| EDGE-195 | Read length > max_read_size rejected | smb2_read_write.c:485-490 | Custom: length=64MB+1 | STATUS_INVALID_PARAMETER | P1 |
| EDGE-196 | Read zero bytes at EOF returns STATUS_END_OF_FILE | smb2_read_write.c:535-540 | Read beyond EOF | STATUS_END_OF_FILE | P1 |
| EDGE-197 | Read fewer bytes than MinimumCount returns STATUS_END_OF_FILE | smb2_read_write.c:535 | MinimumCount=100, only 50 available | STATUS_END_OF_FILE | P1 |
| EDGE-198 | Read without FILE_READ_DATA access denied | smb2_read_write.c:458-462 | Open write-only, try read | STATUS_ACCESS_DENIED | P1 |
| EDGE-199 | Read on directory returns STATUS_INVALID_DEVICE_REQUEST | smb2_read_write.c:655-656 | Read from directory handle | STATUS_INVALID_DEVICE_REQUEST | P1 |
| EDGE-200 | Read with lock conflict returns STATUS_FILE_LOCK_CONFLICT | smb2_read_write.c:657-658 | Read locked range | STATUS_FILE_LOCK_CONFLICT | P1 |
| EDGE-201 | Read closed file returns STATUS_FILE_CLOSED | smb2_read_write.c:659-660 | Read after close | STATUS_FILE_CLOSED | P1 |
| EDGE-202 | Read with sharing violation | smb2_read_write.c:663-664 | Read with sharing conflict | STATUS_SHARING_VIOLATION | P1 |
| EDGE-203 | Read SMB2_READFLAG_READ_UNBUFFERED logged but ignored | smb2_read_write.c:502-504 | Custom: set UNBUFFERED flag | Buffered read, debug log emitted | P2 |
| EDGE-204 | Compound read uses compound_fid | smb2_read_write.c:407-415 | CREATE+READ compound | Read uses CREATE's FID | P1 |
| EDGE-205 | Zero-copy sendfile path (unsigned, unencrypted, non-compound) | smb2_read_write.c:519-573 | Simple read, transport supports sendfile | Data sent via sendfile | P2 |
| EDGE-206 | Compound read copies data inline (no aux iov) | smb2_read_write.c:622-649 | CREATE+READ compound | Data in contiguous buffer | P1 |

#### Read DataOffset

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-207 | DataOffset in response relative to SMB2 header start | smb2_read_write.c:547, 616 | Any read | DataOffset = offsetof(Buffer) | P1 |
| EDGE-208 | DataRemaining set correctly for pipe reads | smb2_read_write.c:291 | Pipe read with overflow | DataRemaining = remaining bytes | P1 |

#### Write Sentinel

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-209 | Write offset 0xFFFFFFFFFFFFFFFF (append-to-EOF sentinel) | smb2_read_write.c:831-841 | Append write with sentinel | Write at i_size | P0 |
| EDGE-210 | Sentinel with FILE_WRITE_DATA (not append-only) rejected | smb2_read_write.c:935-938 | Sentinel on write-capable handle | STATUS_INVALID_PARAMETER | P0 |
| EDGE-211 | Sentinel without FILE_APPEND_DATA rejected | smb2_read_write.c:936 | Sentinel on read-only handle | STATUS_INVALID_PARAMETER | P0 |
| EDGE-212 | Sentinel resolves to i_size_read() | smb2_read_write.c:940 | Append write | Write at current EOF | P1 |

#### Write Validation

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-213 | Write offset < 0 rejected | smb2_read_write.c:837-841 | Custom: negative offset | STATUS_INVALID_PARAMETER | P0 |
| EDGE-214 | Write offset > MAX_LFS_FILESIZE rejected | smb2_read_write.c:837 | Custom: huge offset | STATUS_INVALID_PARAMETER | P0 |
| EDGE-215 | Write offset+length overflow rejected | smb2_read_write.c:846-850 | Custom: overflow | STATUS_INVALID_PARAMETER | P0 |
| EDGE-216 | Write length > max_write_size rejected | smb2_read_write.c:943-948 | Custom: length > max | STATUS_INVALID_PARAMETER | P1 |
| EDGE-217 | Write without FILE_WRITE_DATA or FILE_APPEND_DATA denied | smb2_read_write.c:906-909 | Open read-only, try write | STATUS_ACCESS_DENIED | P1 |
| EDGE-218 | Write on read-only share rejected | smb2_read_write.c:880-884 | Write to read-only share | STATUS_ACCESS_DENIED | P1 |
| EDGE-219 | Write DataOffset < offsetof(Buffer) rejected | smb2_read_write.c:989-992 | Custom: DataOffset too small | STATUS_INVALID_PARAMETER | P0 |
| EDGE-220 | Write DataOffset+Length overflows request buffer | smb2_read_write.c:1005-1010 | Custom: overflow data | STATUS_INVALID_PARAMETER | P0 |
| EDGE-221 | Compound write adjusts buffer length for sub-request | smb2_read_write.c:1002-1003 | CREATE+WRITE compound | Buffer length relative to compound offset | P1 |
| EDGE-222 | Write with WRITE_THROUGH flag triggers fsync | smb2_read_write.c:969-970 | Write with WRITE_THROUGH | Data fsynced | P2 |
| EDGE-223 | Write SMB2_WRITEFLAG_WRITE_UNBUFFERED logged but ignored | smb2_read_write.c:981-983 | Custom: set UNBUFFERED flag | Buffered write, debug log | P2 |
| EDGE-224 | Write ChannelSequence check | smb2_read_write.c:913-917 | Stale ChannelSequence on write | STATUS_FILE_NOT_AVAILABLE | P1 |
| EDGE-225 | Write ENOSPC returns STATUS_DISK_FULL | smb2_read_write.c:1051-1052 | Fill disk, try write | STATUS_DISK_FULL | P1 |
| EDGE-226 | Write EFBIG returns STATUS_DISK_FULL | smb2_read_write.c:1051 | Write exceeding fs limits | STATUS_DISK_FULL | P1 |
| EDGE-227 | Compound write uses compound_fid | smb2_read_write.c:890-897 | CREATE+WRITE compound | Write uses CREATE's FID | P1 |
| EDGE-228 | BranchCache invalidation after write | smb2_read_write.c:1034 | Write to file with cached hash | Hash invalidated | P2 |

#### Fruit/TM Quota Check on Write

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-229 | Time Machine quota exceeded rejects write | smb2_read_write.c:957-964 | Exceed TM quota, try write | Error status | P2 |

#### Flush Edge Cases

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-230 | Flush with invalid FID returns STATUS_FILE_CLOSED | smb2_read_write.c:1106-1111 | Flush with bad FID | STATUS_FILE_CLOSED | P1 |
| EDGE-231 | Flush without write/append access returns STATUS_ACCESS_DENIED | smb2_read_write.c:1117-1124 | Open read-only, flush | STATUS_ACCESS_DENIED | P1 |
| EDGE-232 | Flush ChannelSequence check | smb2_read_write.c:1127-1133 | Stale ChannelSequence on flush | STATUS_FILE_NOT_AVAILABLE | P1 |
| EDGE-233 | Flush compound uses compound_fid | smb2_read_write.c:1088-1095 | CREATE+FLUSH compound | Flush uses CREATE's FID | P1 |
| EDGE-234 | Flush Apple F_FULLFSYNC (Reserved1=0xFFFF) | smb2_read_write.c:1139-1142 | Fruit client flush | Full device sync | P2 |
| EDGE-235 | Flush VFS error returns STATUS_INVALID_HANDLE | smb2_read_write.c:1146-1148 | VFS fsync failure | STATUS_INVALID_HANDLE | P2 |

---

### NEGOTIATE Edge Cases (78 cases)

#### Context Assembly (Response)

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-236 | Preauth context overflow check | smb2_negotiate.c:181-182 | SMB 3.1.1 negotiate with tiny buffer | STATUS_INVALID_PARAMETER | P0 |
| EDGE-237 | Encryption context assembly | smb2_negotiate.c:187-202 | SMB 3.1.1 negotiate with encryption | Encryption context in response | P1 |
| EDGE-238 | Compression context assembly | smb2_negotiate.c:204-218 | SMB 3.1.1 negotiate with compression | Compression context in response | P1 |
| EDGE-239 | Signing capabilities context assembly | smb2_negotiate.c:232-246 | SMB 3.1.1 negotiate with signing caps | Signing context in response | P1 |
| EDGE-240 | RDMA transform context assembly | smb2_negotiate.c:248-263 | RDMA negotiate | RDMA context in response | P2 |
| EDGE-241 | Transport capabilities context assembly | smb2_negotiate.c:265-276 | TLS negotiate | Transport context in response | P2 |
| EDGE-242 | POSIX extensions context assembly | smb2_negotiate.c:220-229 | POSIX negotiate | POSIX context in response | P2 |
| EDGE-243 | Each context 8-byte aligned | smb2_negotiate.c:191, 207, etc. | SMB 3.1.1 with multiple contexts | All contexts 8-byte aligned | P1 |
| EDGE-244 | NegotiateContextOffset in response correct | smb2_negotiate.c:873-874 | SMB 3.1.1 negotiate | Offset = OFFSET_OF_NEG_CONTEXT | P1 |

#### Preauth Decode

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-245 | Preauth context too short | smb2_negotiate.c:292-294 | Custom: truncated preauth | STATUS_INVALID_PARAMETER | P0 |
| EDGE-246 | HashAlgorithmCount=0 rejected | smb2_negotiate.c:301-304 | Custom: zero hash count | STATUS_INVALID_PARAMETER | P0 |
| EDGE-247 | SHA-512 hash algorithm accepted | smb2_negotiate.c:312-316 | Normal negotiate with SHA-512 | Preauth_HashId set | P1 |
| EDGE-248 | Unknown hash algorithm rejected | smb2_negotiate.c:318 | Custom: HashAlgorithm=0x9999 | STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP | P1 |

#### Encrypt Decode

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-249 | Encryption context too short | smb2_negotiate.c:328-331 | Custom: truncated encrypt ctx | Context ignored (no cipher set) | P1 |
| EDGE-250 | CipherCount overflow (multiplication) | smb2_negotiate.c:336-339 | Custom: huge CipherCount | Context ignored | P0 |
| EDGE-251 | CipherCount exceeds context data | smb2_negotiate.c:341-345 | Custom: CipherCount > available | Context ignored | P0 |
| EDGE-252 | Encryption disabled by server config | smb2_negotiate.c:347-348 | Set SMB2_ENCRYPTION_OFF flag | No cipher selected | P1 |
| EDGE-253 | Server cipher preference order (AES-256-GCM first) | smb2_negotiate.c:360-381 | Client offers CCM+GCM | Server picks AES-256-GCM | P1 |
| EDGE-254 | No cipher overlap: cipher_type stays 0 | smb2_negotiate.c:359 | Client offers unknown ciphers | No cipher selected | P1 |

#### Compress Decode

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-255 | Compression context too short | smb2_negotiate.c:412-415 | Custom: truncated compress ctx | STATUS_INVALID_PARAMETER | P0 |
| EDGE-256 | CompressionAlgorithmCount=0 rejected | smb2_negotiate.c:420-423 | Custom: zero algo count | STATUS_INVALID_PARAMETER | P0 |
| EDGE-257 | Algorithm count overflow | smb2_negotiate.c:425-428 | Custom: huge algo count | STATUS_INVALID_PARAMETER | P0 |
| EDGE-258 | Algorithm count exceeds context data | smb2_negotiate.c:430-433 | Custom: count > available | STATUS_INVALID_PARAMETER | P0 |
| EDGE-259 | LZ4 preferred over Pattern_V1 | smb2_negotiate.c:440-446 | Client offers both | LZ4 selected | P2 |
| EDGE-260 | Pattern_V1 selected when no LZ4 | smb2_negotiate.c:448-456 | Client offers Pattern_V1 only | Pattern_V1 selected | P2 |
| EDGE-261 | No algorithm overlap: compress_algorithm stays NONE | smb2_negotiate.c:458-459 | Client offers only LZNT1 | No compression selected | P2 |

#### Signing Decode

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-262 | Signing context too short | smb2_negotiate.c:469-472 | Custom: truncated signing ctx | STATUS_INVALID_PARAMETER | P0 |
| EDGE-263 | SigningAlgorithmCount=0 rejected | smb2_negotiate.c:478-481 | Custom: zero signing count | STATUS_INVALID_PARAMETER | P0 |
| EDGE-264 | Signing count overflow | smb2_negotiate.c:483-484 | Custom: huge signing count | STATUS_INVALID_PARAMETER | P0 |
| EDGE-265 | Signing count exceeds context data | smb2_negotiate.c:486-490 | Custom: count > available | STATUS_INVALID_PARAMETER | P0 |
| EDGE-266 | AES-CMAC preferred over HMAC-SHA256 | smb2_negotiate.c:506-518 | Client offers both | AES-CMAC selected (first match) | P1 |
| EDGE-267 | No signing overlap: fallback to AES-CMAC | smb2_negotiate.c:507 | Client offers unknown algos | AES-CMAC fallback | P1 |
| EDGE-268 | AES-GMAC not offered (compatibility) | smb2_negotiate.c:500-505 | Client offers only GMAC | AES-CMAC fallback | P2 |

#### RDMA/Transport Decode

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-269 | RDMA transform context too short | smb2_negotiate.c:544-547 | Custom: truncated RDMA ctx | Context ignored | P2 |
| EDGE-270 | RDMA TransformCount=0 | smb2_negotiate.c:552-555 | Custom: zero transform count | Context ignored | P2 |
| EDGE-271 | RDMA transform count overflow | smb2_negotiate.c:557-558 | Custom: huge count | Context ignored | P2 |
| EDGE-272 | RDMA transform count exceeds data | smb2_negotiate.c:560-564 | Custom: count > available | Context ignored | P2 |
| EDGE-273 | RDMA transform array full (3 entries max) | smb2_negotiate.c:570-571 | Client offers > 3 transforms | Only first 3 stored | P2 |
| EDGE-274 | Transport capabilities context too short | smb2_negotiate.c:526-529 | Custom: truncated transport ctx | Context ignored | P2 |
| EDGE-275 | Transport level security flag accepted | smb2_negotiate.c:531-534 | Client supports TLS | transport_secured = true | P2 |

#### Deassemble (Request Parsing)

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-276 | Negotiate context offset beyond buffer | smb2_negotiate.c:593-596 | Custom: offset > len_of_smb | Contexts ignored (no error) | P1 |
| EDGE-277 | Context count > 16 rejected | smb2_negotiate.c:605-609 | Custom: 17 contexts | STATUS_INVALID_PARAMETER | P0 |
| EDGE-278 | Context DataLength > remaining bytes | smb2_negotiate.c:621-622 | Custom: short last context | Parsing stops (break) | P1 |
| EDGE-279 | Duplicate PREAUTH context rejected | smb2_negotiate.c:627-631 | Custom: two PREAUTH contexts | STATUS_INVALID_PARAMETER | P0 |
| EDGE-280 | Duplicate ENCRYPTION context rejected | smb2_negotiate.c:641-644 | Custom: two ENCRYPTION contexts | STATUS_INVALID_PARAMETER | P0 |
| EDGE-281 | Duplicate COMPRESSION context rejected | smb2_negotiate.c:652-655 | Custom: two COMPRESSION contexts | STATUS_INVALID_PARAMETER | P0 |
| EDGE-282 | Duplicate RDMA context rejected | smb2_negotiate.c:704-707 | Custom: two RDMA contexts | STATUS_INVALID_PARAMETER | P0 |
| EDGE-283 | NETNAME context validates against server name | smb2_negotiate.c:672-689 | Normal negotiate with server name | Debug log if mismatch | P2 |
| EDGE-284 | POSIX extension context sets flag | smb2_negotiate.c:693 | POSIX-capable client | posix_ext_supported = true | P2 |
| EDGE-285 | Context offsets 8-byte aligned during parsing | smb2_negotiate.c:724 | Normal negotiate | 8-byte alignment per context | P1 |

#### Handle Negotiate

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-286 | Second NEGOTIATE on established connection disconnects | smb2_negotiate.c:751-761 | Send two NEGOTIATEs | Connection disconnected, no response | P0 |
| EDGE-287 | Zero response body to prevent heap data leakage | smb2_negotiate.c:746-747 | First negotiate | No stale data in response | P0 |
| EDGE-288 | DialectCount=0 rejected | smb2_negotiate.c:772-777 | Custom: zero dialects | STATUS_INVALID_PARAMETER | P0 |
| EDGE-289 | Dialect array exceeds negotiate context offset (3.1.1) | smb2_negotiate.c:794-799 | Custom: dialects overflow into contexts | STATUS_INVALID_PARAMETER | P0 |
| EDGE-290 | Dialect array exceeds buffer (non-3.1.1) | smb2_negotiate.c:801-806 | Custom: dialects overflow buffer | STATUS_INVALID_PARAMETER | P0 |
| EDGE-291 | SMB 3.1.1 negotiate context offset before dialects end | smb2_negotiate.c:788-792 | Custom: contexts overlap dialects | STATUS_INVALID_PARAMETER | P0 |
| EDGE-292 | SMB 3.1.1 context offset beyond buffer | smb2_negotiate.c:782-786 | Custom: offset > buf_len | STATUS_INVALID_PARAMETER | P0 |
| EDGE-293 | SMB 3.1.1 without PREAUTH context rejected | smb2_negotiate.c:851-859 | Custom: 3.1.1 without preauth ctx | STATUS_INVALID_PARAMETER | P0 |
| EDGE-294 | Preauth hash generated on successful negotiate | smb2_negotiate.c:870-872 | Normal 3.1.1 negotiate | Preauth_HashValue populated | P1 |
| EDGE-295 | SMB 3.0.2 init | smb2_negotiate.c:886-893 | Negotiate 3.0.2 | init_smb3_02_server called | P1 |
| EDGE-296 | SMB 3.0 init | smb2_negotiate.c:894-901 | Negotiate 3.0 | init_smb3_0_server called | P1 |
| EDGE-297 | SMB 2.1 init | smb2_negotiate.c:902-908 | Negotiate 2.1 | init_smb2_1_server called | P1 |
| EDGE-298 | SMB 2.0.2 init | smb2_negotiate.c:910-917 | Negotiate 2.0.2 | init_smb2_0_server called | P1 |
| EDGE-299 | SMB2X / BAD_PROT_ID rejected | smb2_negotiate.c:918-926 | Custom: unsupported dialect | STATUS_NOT_SUPPORTED | P1 |
| EDGE-300 | conn->vals freed before re-allocation (no leak) | smb2_negotiate.c:818-819 | Negotiate after prior negotiate attempt | Old vals freed | P0 |
| EDGE-301 | Old vals restored on error path | smb2_negotiate.c:830-831 | Negotiate error | conn->vals not NULL | P0 |
| EDGE-302 | ServerGUID generated once and stable | smb2_negotiate.c:954-959 | Two connections | Same ServerGUID | P1 |
| EDGE-303 | ServerStartTime recorded once | smb2_negotiate.c:965-966 | Two connections | Same StartTime | P2 |
| EDGE-304 | ClientGUID saved for all SMB2 dialects (>= SMB2.0.2) | smb2_negotiate.c:940-943 | Negotiate any SMB2 dialect | ClientGUID stored | P1 |
| EDGE-305 | SecurityMode SIGNING_REQUIRED set for mandatory signing | smb2_negotiate.c:981-983 | Server signing=mandatory | SIGNING_REQUIRED in response | P1 |
| EDGE-306 | Auto signing: enabled if client advertises capability | smb2_negotiate.c:984-993 | Server signing=auto, client has ENABLED | conn->sign = true | P1 |
| EDGE-307 | Disabled signing: still required if client requires it | smb2_negotiate.c:993-996 | Server disabled, client REQUIRED | conn->sign = true | P1 |
| EDGE-308 | cli_sec_mode saved for all dialects | smb2_negotiate.c:943 | Negotiate | cli_sec_mode stored | P2 |
| EDGE-309 | preauth_info freed on negotiate error | smb2_negotiate.c:841-843 | Error during 3.1.1 negotiate | No memory leak | P0 |

---

### SESSION Edge Cases (98 cases)

#### Preauth Hash

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-310 | Preauth hash computed for SESSION_SETUP request | smb2_session.c (hash path) | SMB 3.1.1 session setup | Hash updated with request | P1 |
| EDGE-311 | Preauth hash computed for SESSION_SETUP response | smb2_session.c (hash path) | SMB 3.1.1 session setup | Hash updated with response | P1 |
| EDGE-312 | Preauth hash copied to session on bind | smb2_session.c (bind path) | Multichannel bind | Session preauth hash set | P1 |
| EDGE-313 | Preauth hash integrity maintained across MORE_PROCESSING legs | smb2_session.c | Multi-leg SPNEGO | Hash chain correct | P1 |
| EDGE-314 | Preauth hash used for encryption key derivation (3.1.1) | smb2_session.c | 3.1.1 session with encryption | Keys derived from preauth hash | P1 |
| EDGE-315 | No preauth hash for non-3.1.1 dialects | smb2_session.c | SMB 3.0 session setup | No hash computation | P2 |
| EDGE-316 | Preauth hash reset on re-authentication | smb2_session.c | Session re-auth | Hash reset to negotiate value | P2 |

#### NTLM Negotiate/Authenticate

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-317 | NTLMSSP_NEGOTIATE message initiates challenge | auth.c | Normal NTLM auth | Challenge response | P1 |
| EDGE-318 | NTLMSSP_AUTH with valid credentials succeeds | auth.c | Normal NTLM auth | Session established | P1 |
| EDGE-319 | NTLMSSP_AUTH with invalid password fails | auth.c | Wrong password | STATUS_LOGON_FAILURE | P1 |
| EDGE-320 | NTLMSSP_AUTH with unknown user fails | auth.c | Unknown username | STATUS_LOGON_FAILURE | P1 |
| EDGE-321 | NTLMSSP_ANONYMOUS with zero NtChallengeResponse length | auth.c | Anonymous auth | Session with null user | P1 |
| EDGE-322 | NTLMSSP_ANONYMOUS sets IS_NULL flag | smb2_session.c | Anonymous auth | SMB2_SESSION_FLAG_IS_NULL_LE | P1 |
| EDGE-323 | NTLM challenge has correct flags | auth.c | NTLM negotiate | Flags include NTLMSSP_* | P2 |
| EDGE-324 | NTLMv2 response validated correctly | auth.c | NTLMv2 auth | Correct hash comparison | P1 |
| EDGE-325 | LM response ignored for security | auth.c | NTLMv2 with LM | LM not used for auth | P2 |
| EDGE-326 | SPNEGO wrapping parsed correctly | asn1.c | GSSAPI session setup | SPNEGO unwrapped | P1 |
| EDGE-327 | SPNEGO mechListMIC validated | asn1.c | SPNEGO with MIC | MIC verified | P2 |
| EDGE-328 | Kerberos ticket accepted via SPNEGO | auth.c | Kerberos auth | Ticket validated by daemon | P1 |
| EDGE-329 | Extended security blob too short | smb2_session.c | Custom: truncated blob | STATUS_INVALID_PARAMETER | P0 |
| EDGE-330 | Extended security blob offset+length overflow | smb2_session.c | Custom: overflow | STATUS_INVALID_PARAMETER | P0 |

#### Session Setup Main Path

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-331 | Session setup on non-negotiated connection rejected | smb2_session.c | Skip negotiate, send session setup | STATUS_INVALID_PARAMETER | P0 |
| EDGE-332 | Session setup creates new session | smb2_session.c | First session setup | New session allocated | P1 |
| EDGE-333 | Session binding (SMB2_SESSION_FLAG_BINDING) | smb2_session.c | Multichannel session bind | Second channel bound | P1 |
| EDGE-334 | Session binding requires signing | smb2_session.c | Binding without signed request | STATUS_INVALID_PARAMETER | P1 |
| EDGE-335 | Session re-authentication with same SessionId | smb2_session.c | Re-auth on existing session | Session re-authenticated | P1 |
| EDGE-336 | Session setup MORE_PROCESSING_REQUIRED (multi-leg) | smb2_session.c | SPNEGO multi-leg auth | STATUS_MORE_PROCESSING_REQUIRED | P1 |
| EDGE-337 | Session setup final leg completes authentication | smb2_session.c | SPNEGO final leg | STATUS_SUCCESS | P1 |
| EDGE-338 | Session encryption key generated after auth | smb2_session.c | Encrypted session | Encryption key available | P1 |
| EDGE-339 | Session signing key generated after auth | smb2_session.c | Signed session | Signing key available | P1 |
| EDGE-340 | Maximum sessions per connection enforced | smb2_session.c | Open many sessions | Limit enforced | P2 |
| EDGE-341 | Session setup allocates unique SessionId | smb2_session.c | Multiple sessions | Unique IDs | P2 |
| EDGE-342 | Session encryption enforcement (encrypted-only after setup) | server.c | Unencrypted request on encrypted session | STATUS_ACCESS_DENIED + disconnect | P0 |
| EDGE-343 | Session closed notification sent to channels | smb2_misc_cmds.c | Logoff on multichannel | Notification to other channels | P1 |
| EDGE-344 | Session logoff closes all files | smb2_tree.c | Logoff | All files closed | P1 |
| EDGE-345 | Session logoff sends notification before closing files | smb2_tree.c | Logoff | Notification before close | P1 |
| EDGE-346 | Guest session (no user credentials) | smb2_session.c | Guest login | Limited access session | P1 |
| EDGE-347 | Session ID 0 in request matches any session (wildcard) | smb2_session.c | SessionId=0 | Session resolved | P2 |

#### Tree Connect

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-348 | Tree connect to valid share | smb2_tree.c | `smbclient //server/share` | Tree connected | P1 |
| EDGE-349 | Tree connect to non-existent share | smb2_tree.c | `smbclient //server/bogus` | STATUS_BAD_NETWORK_NAME | P1 |
| EDGE-350 | Tree connect share name >= 80 chars rejected | smb2_tree.c | Custom: 80-char share name | STATUS_BAD_NETWORK_NAME | P1 |
| EDGE-351 | Tree connect extension (EXTENSION_PRESENT flag) path parsing | smb2_tree.c | SMB 3.1.1 tree connect with extension | PathOffset relative to Buffer[0] | P1 |
| EDGE-352 | Tree connect on IPC$ share | smb2_tree.c | `smbclient //server/IPC$` | IPC pipe share connected | P1 |
| EDGE-353 | Tree disconnect releases all handles | smb2_tree.c | Tree disconnect | Handles released | P1 |
| EDGE-354 | Tree connect writable flag set for writable shares | smb2_tree.c | Connect to writable share | KSMBD_TREE_CONN_FLAG_WRITABLE | P1 |

#### Session/Tree Error Conditions

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-355 | Request with invalid SessionId | smb2_pdu_common.c | Custom: bogus SessionId | STATUS_USER_SESSION_DELETED | P1 |
| EDGE-356 | Request with invalid TreeId | smb2_pdu_common.c | Custom: bogus TreeId | STATUS_NETWORK_NAME_DELETED | P1 |
| EDGE-357 | Request without active session | smb2_pdu_common.c | Request before session setup | STATUS_USER_SESSION_DELETED | P1 |
| EDGE-358 | Request without tree connect | smb2_pdu_common.c | Request before tree connect | STATUS_NETWORK_NAME_DELETED | P1 |

#### Channel Sequence Tracking

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-359 | ChannelSequence tracked per-file | smb2_pdu_common.c | Write with new ChannelSequence | fp->channel_sequence updated | P1 |
| EDGE-360 | Stale ChannelSequence rejected (s16 diff) | smb2_pdu_common.c | Write with old ChannelSequence | STATUS_FILE_NOT_AVAILABLE | P1 |
| EDGE-361 | ChannelSequence wrap-around detection | smb2_pdu_common.c | ChannelSequence wrap from 0xFFFF to 0x0000 | Correct wrap detection | P1 |
| EDGE-362 | ChannelSequence checked on WRITE | smb2_read_write.c:913 | Write with stale sequence | STATUS_FILE_NOT_AVAILABLE | P1 |
| EDGE-363 | ChannelSequence checked on FLUSH | smb2_read_write.c:1127 | Flush with stale sequence | STATUS_FILE_NOT_AVAILABLE | P1 |
| EDGE-364 | ChannelSequence checked on LOCK | smb2_lock.c:540 | Lock with stale sequence | STATUS_FILE_NOT_AVAILABLE | P1 |
| EDGE-365 | ChannelSequence checked on SET_INFO | smb2_query_set.c | Set info with stale sequence | STATUS_FILE_NOT_AVAILABLE | P1 |
| EDGE-366 | ChannelSequence checked on IOCTL (when has file_id) | smb2_ioctl.c | IOCTL with stale sequence | STATUS_FILE_NOT_AVAILABLE | P1 |

#### CANCEL Command

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-367 | CANCEL sends no response (send_no_response=1) | smb2_lock.c:230 | SMB2 CANCEL | No response sent | P1 |
| EDGE-368 | CANCEL not signed (MS-SMB2 spec exemption) | smb2_pdu_common.c | Unsigned CANCEL on signed session | CANCEL accepted | P1 |

---

### SERVER Core Edge Cases (52 cases)

#### Request Processing

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-369 | Request with SMB2 header too short rejected | server.c | Custom: truncated header | Connection dropped | P0 |
| EDGE-370 | Request with invalid ProtocolId rejected | server.c | Custom: bad magic | Connection dropped | P0 |
| EDGE-371 | Request exceeds max transaction size | server.c | Custom: huge request | STATUS_INVALID_PARAMETER | P1 |
| EDGE-372 | Credit request/grant processing | smb2_misc.c | Normal requests | Credits granted/consumed | P1 |
| EDGE-373 | Zero-credit request handling | smb2_misc.c | Request with CreditRequest=0 | At least 1 credit granted | P2 |
| EDGE-374 | Credit overflow prevention | smb2_misc.c | Excessive credit requests | Capped at max credits | P1 |
| EDGE-375 | Non-LARGE_MTU dialect credit tracking | smb2_misc.c | SMB 2.0.2 credit management | Single credit per request | P1 |

#### Compound Handling

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-376 | Simple compound (CREATE+READ+CLOSE) | smb2_pdu_common.c | `smbtorture smb2.compound.simple` | All three succeed | P1 |
| EDGE-377 | Compound with RELATED_OPERATIONS flag | smb2_pdu_common.c | `smbtorture smb2.compound.related1` | FID propagated | P1 |
| EDGE-378 | Compound FID captured from CREATE response | smb2_pdu_common.c | CREATE+READ compound | compound_fid set from CREATE | P1 |
| EDGE-379 | Compound FID captured from non-CREATE commands | smb2_pdu_common.c | FLUSH+CLOSE compound | compound_fid set from FLUSH | P1 |
| EDGE-380 | Compound error propagation: CREATE failure cascades | smb2_pdu_common.c | CREATE fails + READ | READ gets STATUS_INVALID_HANDLE | P1 |
| EDGE-381 | Compound error propagation: non-CREATE failure does NOT cascade | smb2_pdu_common.c | READ fails + CLOSE | CLOSE still attempted | P1 |
| EDGE-382 | Compound 8-byte padding between members | smb2_pdu_common.c | Multi-part compound | 8-byte aligned boundaries | P1 |
| EDGE-383 | NextCommand offset validation | smb2_pdu_common.c | Custom: invalid NextCommand | STATUS_INVALID_PARAMETER | P0 |
| EDGE-384 | Compound response buffer overflow prevention | smb2_pdu_common.c | Large compound response | No buffer overflow | P0 |
| EDGE-385 | Compound FID from FLUSH command | smb2_pdu_common.c | `smbtorture smb2.compound.flush_close` | FID from FLUSH | P1 |
| EDGE-386 | Compound FID from WRITE command | smb2_pdu_common.c | `smbtorture smb2.compound.write` | FID from WRITE | P1 |
| EDGE-387 | Compound FID from READ command | smb2_pdu_common.c | Compound with READ | FID from READ | P1 |
| EDGE-388 | Compound FID from CLOSE command | smb2_pdu_common.c | Compound with CLOSE | FID from CLOSE | P1 |
| EDGE-389 | Compound FID from QUERY_INFO command | smb2_pdu_common.c | Compound with QUERY_INFO | FID from QUERY_INFO | P1 |
| EDGE-390 | Compound FID from SET_INFO command | smb2_pdu_common.c | Compound with SET_INFO | FID from SET_INFO | P1 |
| EDGE-391 | Compound FID from LOCK command | smb2_pdu_common.c | Compound with LOCK | FID from LOCK | P1 |
| EDGE-392 | Compound FID from IOCTL command | smb2_pdu_common.c | Compound with IOCTL | FID from IOCTL | P1 |
| EDGE-393 | Compound FID from QUERY_DIR command | smb2_pdu_common.c | Compound with QUERY_DIR | FID from QUERY_DIR | P1 |
| EDGE-394 | Compound FID from CHANGE_NOTIFY command | smb2_pdu_common.c | Compound with CHANGE_NOTIFY | FID from CHANGE_NOTIFY | P1 |
| EDGE-395 | Compound interim response (smb2.compound.interim1/2/3) | smb2_pdu_common.c | `smbtorture smb2.compound.interim*` | Interim responses correct | P1 |

#### Encryption/Signing in Request Processing

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-396 | Encrypted request decrypted before processing | server.c | Encrypted session request | Request decrypted | P1 |
| EDGE-397 | Unencrypted request on encrypted session rejected | server.c | Custom: unencrypted on encrypted | STATUS_ACCESS_DENIED + disconnect | P0 |
| EDGE-398 | Signed request verified | server.c | Signed request | Signature verified | P1 |
| EDGE-399 | Invalid signature rejected | server.c | Custom: bad signature | STATUS_ACCESS_DENIED | P0 |

#### Work Queue

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-400 | Work item allocation | ksmbd_work.c | Normal request | Work struct allocated | P2 |
| EDGE-401 | Work item freed after processing | ksmbd_work.c | Normal request | Work struct freed | P2 |
| EDGE-402 | Async work setup and interim response | smb2_pdu_common.c | Blocking lock | Async work created | P1 |
| EDGE-403 | Async work cancel callback invocation | smb2_pdu_common.c | Cancel async work | Callback called | P1 |
| EDGE-404 | Outstanding async credit tracking | smb2_pdu_common.c | Many async requests | Credits tracked | P1 |
| EDGE-405 | Async credit limit enforcement | smb2_pdu_common.c | Exceed async limit | STATUS_INSUFFICIENT_RESOURCES | P1 |
| EDGE-406 | release_async_work cleanup | smb2_pdu_common.c | Lock retry after wait | Async resources freed | P2 |

#### Init/Shutdown

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-407 | Server state transitions (STARTING -> RUNNING) | server.c | Module load | State = RUNNING | P2 |
| EDGE-408 | Server shutdown closes all connections | server.c | ksmbd.control -s | All connections closed | P1 |
| EDGE-409 | Connection cleanup on disconnect | connection.c | Client disconnect | Resources freed | P1 |
| EDGE-410 | Connection hash table (CONN_HASH_SIZE buckets) | connection.c | Multiple connections | Hash distribution | P2 |
| EDGE-411 | Max connections per IP enforcement | connection.c | Many connections from one IP | Limit enforced | P1 |
| EDGE-412 | Connection idle timeout | connection.c | Idle connection | Timed out | P2 |
| EDGE-413 | Transport layer selection (TCP/RDMA/QUIC) | transport_tcp.c | Connection on different transports | Correct transport selected | P2 |

#### SMB1 Handling

| ID | Description | Source | Test Method | Expected | Pri |
|----|-------------|--------|-------------|----------|-----|
| EDGE-414 | SMB1 negotiate with "\2NT LANMAN 1.0" alias | smb1pdu.c | smbclient negotiate | Dialect matched | P1 |
| EDGE-415 | SMB1 upgrade to SMB2 uses wildcard dialect 0x02FF | smb1pdu.c | SMB1 negotiate -> SMB2 upgrade | Dialect 0x02FF in response | P1 |
| EDGE-416 | SMB1 smb1_conn flag set | smb1pdu.c | Pure SMB1 connection | conn->smb1_conn = true | P1 |
| EDGE-417 | SMB1 deprecation warning emitted | smb1pdu.c | SMB1 negotiate | pr_warn_ratelimited | P2 |
| EDGE-418 | SMB1 CAP_LOCK_AND_READ removed from capabilities | smb1pdu.c | SMB1 negotiate | No CAP_LOCK_AND_READ | P2 |
| EDGE-419 | SMB2.0.2 deprecation warning emitted | smb_common.c | SMB 2.0.2 negotiate | pr_warn_ratelimited | P2 |
| EDGE-420 | conn->vals freed before re-alloc in negotiate paths | smb_common.c | Repeated negotiates | No memory leak | P0 |
| EDGE-421 | SMB1 to SMB2 upgrade: conn->vals re-allocated | smb_common.c | SMB1 upgrade | New vals allocated | P1 |

---

## Bug Regression Tests

For each bug previously fixed (from MEMORY.md), a specific regression test
ensures the fix is not reverted.

### Session 2026-02-28 Fixes

| ID | Description | Root Cause | Test Method | Expected | Source |
|----|-------------|-----------|-------------|----------|--------|
| REG-001 | SMB2.0.2 credit underflow (non-LARGE_MTU credit tracking) | Missing else branch in smb2misc.c for non-LARGE_MTU | Connect with SMB 2.0.2, send multiple requests | Credits tracked correctly, no underflow | smb2misc.c |
| REG-002 | SMB2.0.2 validate negotiate (ClientGUID copy for all dialects >= SMB2) | ClientGUID/cli_sec_mode only copied for > SMB2 (not >=) | `smbtorture smb2.ioctl.validate_negotiate` with SMB 2.0.2 | FSCTL_VALIDATE_NEGOTIATE_INFO succeeds | smb2_negotiate.c:940-943 |
| REG-003 | SMB1 dialect "\2NT LANMAN 1.0" alias | smbclient sends "\2NT LANMAN 1.0" not "\2NT LM 0.12" | `smbclient -m NT1 //server/share` | SMB1 negotiate succeeds | smb_common.c |
| REG-004 | SMB1 upgrade wildcard dialect 0x02FF | Specific dialect used instead of wildcard in upgrade response | SMB1 negotiate -> auto upgrade to SMB2 | Response dialect = 0x02FF | smb1pdu.c |
| REG-005 | conn->vals memory leak in negotiate paths | kfree not called before re-allocating conn->vals | Multiple negotiates (fuzz test) | No memory leak (kmemleak clean) | smb2_negotiate.c:818-929 |

### Session 2026-03-01a Fixes

| ID | Description | Root Cause | Test Method | Expected | Source |
|----|-------------|-----------|-------------|----------|--------|
| REG-006 | Lock fl_end off-by-one (inclusive end) | POSIX fl_end is inclusive, was set to fl_start + length (not -1) | `smbtorture smb2.lock.rw-shared` with adjacent ranges | Adjacent ranges do not conflict | smb2_lock.c:623-624 |
| REG-007 | Lock OFFSET_MAX skip | Locks beyond OFFSET_MAX caused VFS errors | Lock at offset 2^63+1 | VFS call skipped, ksmbd tracks internally | smb2_lock.c:884-887 |
| REG-008 | Lock overlap with wrap-around | Overlap check did not handle end=0 (wrap to 2^64) | Lock at offset=~0, length=1 | Correct overlap detection | smb2_lock.c:827-840 |
| REG-009 | Compound error propagation (only CREATE cascades) | All compound errors cascaded, breaking FLUSH+CLOSE patterns | `smbtorture smb2.compound.flush_close` | Non-CREATE errors do not cascade | smb2_pdu_common.c |
| REG-010 | Outstanding async counter leak | Async counter not decremented on cancel/completion | Many lock cancel operations | Counter stays at 0 after all cancel | smb2_pdu_common.c |

### Session 2026-03-01b Fixes

| ID | Description | Root Cause | Test Method | Expected | Source |
|----|-------------|-----------|-------------|----------|--------|
| REG-011 | DESIRED_ACCESS_MASK includes SYNCHRONIZE | Mask was 0xF20F01FF, missing SYNCHRONIZE bit 20 | `smbtorture smb2.create.gentest --target=win7` | Access with SYNCHRONIZE accepted (mask=0xF21F01FF) | smb2pdu.h |
| REG-012 | Anonymous re-auth with zero NtChallengeResponse | NTLMSSP_ANONYMOUS rejected when NtChallengeResponse.Length==0 | Anonymous auth | Session created with null user | auth.c |
| REG-013 | dot_dotdot reset on RESTART_SCANS | RESTART_SCANS did not reset dot_dotdot[0/1] | `smbtorture smb2.dir.one` with RESTART_SCANS | Dots re-enumerated after restart | smb2_dir.c |
| REG-014 | Delete-on-close deferred to last closer | Aggressive unlink when other handles still open | Open with DOC, second handle still open, close first | No unlink until last handle closes | vfs_cache.c |

### Session 2026-03-01c Fixes

| ID | Description | Root Cause | Test Method | Expected | Source |
|----|-------------|-----------|-------------|----------|--------|
| REG-015 | Lock sequence bit extraction reversed | Was (val>>28)&0xF/(val>>24)&0xF, should be val&0xF/(val>>4) | Durable handle lock with specific LockSequenceNumber | Correct seq_num/seq_idx extraction | smb2_lock.c:438-439 |
| REG-016 | Lock sequence replay returned -EAGAIN instead of STATUS_OK | Replay detection returned error instead of success | Lock replay on resilient handle | STATUS_OK immediately | smb2_lock.c:454-458 |
| REG-017 | Lock sequence array too small (16 -> 65) | Array lock_seq[16] could not hold indices 1-64 | Lock with seq_idx between 17 and 64 | No array out-of-bounds | vfs_cache.h |
| REG-018 | Lock sequence no valid tracking (0xFF sentinel) | No way to distinguish valid from uninitialized entries | Fresh handle, check replay on unused index | 0xFF means "not valid", no false replay | smb2_lock.c:454 |
| REG-019 | Lock sequence stored before lock processed | Sequence stored on entry, should be stored after success only | Lock that fails (conflict) | Sequence NOT stored | smb2_lock.c:988 |

### Session 2026-03-01d/e/f Fixes

| ID | Description | Root Cause | Test Method | Expected | Source |
|----|-------------|-----------|-------------|----------|--------|
| REG-020 | Second NEGOTIATE rejection | Second negotiate was processed, causing state corruption | Send two NEGOTIATE requests on same connection | Connection disconnected, no response to second | smb2_negotiate.c:751-761 |
| REG-021 | Duplicate negotiate contexts | Duplicate contexts (PREAUTH/ENCRYPT/COMPRESS/RDMA) silently ignored | Custom: send duplicate PREAUTH context | STATUS_INVALID_PARAMETER | smb2_negotiate.c:627-631 |
| REG-022 | IOCTL Flags==0 rejection | IOCTL Flags != SMB2_0_IOCTL_IS_FSCTL was silently processed | Custom: IOCTL with Flags=0 | STATUS_INVALID_PARAMETER | smb2_ioctl.c |
| REG-023 | FILE_DELETE_ON_CLOSE without FILE_DELETE access | DOC accepted without verifying DELETE in GrantedAccess | Open without DELETE access, request DOC | STATUS_ACCESS_DENIED | smb2_create.c:2477-2480 |
| REG-024 | FILE_APPEND_DATA-only rejects non-EOF writes | Writes at arbitrary offsets accepted on append-only handles | Open with APPEND only, write at offset 0 | STATUS_INVALID_PARAMETER | smb2_read_write.c |
| REG-025 | Session encryption enforcement | Unencrypted requests on encrypted sessions were processed | Send unencrypted request on encrypted session | STATUS_ACCESS_DENIED + disconnect | server.c |
| REG-026 | Channel sequence tracking | No per-file ChannelSequence tracking; stale operations not detected | Send write with stale ChannelSequence | STATUS_FILE_NOT_AVAILABLE | smb2_pdu_common.c |
| REG-027 | Tree connect extension path parsing | EXTENSION_PRESENT flag: PathOffset was relative to header, not Buffer[0] | SMB 3.1.1 tree connect with extension | Path correctly parsed | smb2_tree.c |
| REG-028 | Session closed notification | No notification sent to other channels on logoff | Multichannel logoff | Notification sent to other channels | smb2_misc_cmds.c |

### Session 2026-03-01g Fixes

| ID | Description | Root Cause | Test Method | Expected | Source |
|----|-------------|-----------|-------------|----------|--------|
| REG-029 | WRITE sentinel 0xFFFFFFFFFFFFFFFF | Sentinel value rejected by `offset < 0` guard before special handling | Append write with offset=0xFFFFFFFFFFFFFFFF on append handle | Write at EOF succeeds | smb2_read_write.c:831-841 |
| REG-030 | SigningAlgorithmCount=0 rejection | Count=0 accepted without error | Custom: SigningAlgorithmCount=0 | STATUS_INVALID_PARAMETER | smb2_negotiate.c:478-481 |
| REG-031 | CompressionAlgorithmCount=0 rejection | Count=0 accepted without error | Custom: CompressionAlgorithmCount=0 | STATUS_INVALID_PARAMETER | smb2_negotiate.c:420-423 |
| REG-032 | Flush access check | Flush accepted without verifying write/append access | Open read-only, flush | STATUS_ACCESS_DENIED | smb2_read_write.c:1117-1124 |
| REG-033 | Flush not-found returns FILE_CLOSED | Flush on invalid FID returned STATUS_INVALID_HANDLE | Flush with invalid FID | STATUS_FILE_CLOSED | smb2_read_write.c:1108 |

### Session 2026-03-02 Fixes

| ID | Description | Root Cause | Test Method | Expected | Source |
|----|-------------|-----------|-------------|----------|--------|
| REG-034 | Compound FID from non-CREATE commands | init_chained_smb2_rsp only extracted FID from CREATE | `smbtorture smb2.compound.flush_close` | FID extracted from FLUSH | smb2_pdu_common.c |
| REG-035 | FSCTL_SET_SPARSE no-buffer default | Missing buffer treated as error instead of SetSparse=TRUE | FSCTL_SET_SPARSE with empty buffer | File marked sparse (default=TRUE) | ksmbd_fsctl.c, smb2_ioctl.c |
| REG-036 | FILE_DELETE_ON_CLOSE + READONLY = STATUS_CANNOT_DELETE | DOC on readonly file returned generic error, not CANNOT_DELETE | Mark file readonly, open with DOC | STATUS_CANNOT_DELETE | smb2_create.c:2486-2492 |
| REG-037 | GENERIC_EXECUTE pre-expansion | GENERIC_EXECUTE not mapped to specific bits before access check | Open with GENERIC_EXECUTE | Mapped to READ_ATTRIBUTES+EXECUTE+SYNCHRONIZE | smb2_create.c:1931 |
| REG-038 | Directory lease granting | Directory opens stripped all lease states instead of just WRITE | Open directory with RH lease | RH lease granted (not NONE) | smb2_create.c:2365-2367 |
| REG-039 | Directory lease Handle break | Handle caching break on directory not sent to other openers | Hold RH lease on dir, second open | Handle break to R sent | oplock.c |
| REG-040 | smb_break_parent_dir_lease | Parent lease break not triggered on child create/rename | Hold parent key lease, create child file | Parent lease break notification | smb2_create.c:2375 |

---

## Summary Statistics

### Edge Cases by Category

| Category | Count | P0 | P1 | P2 |
|----------|-------|------|------|------|
| CREATE | 112 | 14 | 73 | 25 |
| LOCK | 69 | 4 | 53 | 12 |
| READ/WRITE | 92 | 14 | 50 | 28 |
| NEGOTIATE | 78 | 18 | 37 | 23 |
| SESSION | 98 | 6 | 68 | 24 |
| SERVER Core | 52 | 7 | 30 | 15 |
| **Total Edge Cases** | **501** | **63** | **311** | **127** |

### Regression Tests by Session

| Session | Count |
|---------|-------|
| 2026-02-28 | 5 |
| 2026-03-01a | 5 |
| 2026-03-01b | 4 |
| 2026-03-01c | 5 |
| 2026-03-01d/e/f | 9 |
| 2026-03-01g | 5 |
| 2026-03-02 | 7 |
| **Total Regressions** | **40** |

### Grand Total

| Type | Count |
|------|-------|
| Edge Cases (Source-Derived) | 501 |
| Regression Tests (Bug-Derived) | 40 |
| **Grand Total** | **541** |

### Coverage by Test Method

| Method | Estimated Count |
|--------|----------------|
| smbtorture subtests (existing) | ~180 |
| Custom raw SMB2 client (Python/C) | ~200 |
| smbclient commands | ~40 |
| Debug log inspection | ~30 |
| Memory leak tools (kmemleak) | ~10 |
| OOM simulation | ~10 |
| Configuration-based | ~20 |
| RDMA-specific (requires RDMA setup) | ~15 |
| Race condition tests | ~5 |
| Multichannel tests | ~15 |
| Fruit/macOS tests | ~16 |

### Priority Distribution

- **P0 (Security-Critical)**: 63 edge cases -- MUST pass before any release
- **P1 (Correctness)**: 311 edge cases -- Required for protocol compliance
- **P2 (Robustness)**: 127 edge cases -- Nice-to-have for production quality

---

## Test Execution Notes

1. **P0 tests** should be run on every commit. Failures indicate security
   vulnerabilities or data corruption risks.

2. **P1 tests** should be run in CI on every PR. Failures indicate protocol
   non-compliance that will cause interoperability issues with Windows,
   macOS, or Samba clients.

3. **P2 tests** should be run in nightly builds. Failures indicate
   robustness issues that may manifest under unusual conditions.

4. **RDMA tests** (EDGE-182 through EDGE-191, EDGE-240, EDGE-269-273)
   require an RDMA-capable test environment with SoftRoCE or physical
   InfiniBand hardware.

5. **Multichannel tests** (EDGE-333, EDGE-334, EDGE-343, REG-026, REG-028)
   require a multi-NIC VM or namespace-based setup.

6. **Custom raw SMB2 client tests** can be implemented using Python's
   `impacket` library or a purpose-built C client using `libsmb2`.

7. **smbtorture** is the primary test harness. The ksmbd VM fleet
   (VM3: port 13022/13445, VM4: port 14022/14445) is pre-configured
   for running these tests.

8. **Regression tests** (REG-001 through REG-040) are the highest priority
   subset and should be automated as a regression gate in CI.
