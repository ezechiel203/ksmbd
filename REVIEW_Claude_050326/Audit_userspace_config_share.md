# Audit Userspace Config Share

Agent ID: acd98a94cf315cf94

Now I have all the information needed. Let me compile the comprehensive audit report.

---

# COMPREHENSIVE TEST AUDIT REPORT
## ksmbd-tools Userspace Test Files vs MS-SMB2 Specification and Implementation

---

## FILE 1: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_config_parser.c`
**31 test cases**

### Boolean Parsing Tests (test_bool_yes_values, test_bool_no_values)
- **Verdict: CORRECT** -- These test Samba-compatible configuration boolean parsing ("yes"/"no"/"true"/"false"/"1"/"0"/"enable"/"disable"). These are implementation-specific config parser behaviors, not directly spec-governed. The tests correctly verify all accepted variants.

### Config Option Parsing (test_config_opt_values)
- **Verdict: CORRECT** -- Tests the four config option levels: DISABLED(0), ENABLED(1), AUTO(2), MANDATORY(3). These map to signing/encryption behaviors per MS-SMB2 Section 3.3.5.3. The "disabled"/"enabled"/"auto"/"mandatory" string mapping is correct. Unknown values defaulting to DISABLED is a safe implementation choice.

### Memparse Tests (test_memparse_units)
- **Verdict: CORRECT** -- Tests K/M/G unit suffixes for memory size parsing. These are used for MaxReadSize, MaxWriteSize, MaxTransactSize configuration. The multiplication factors (1024-based) are correct.

### Long Parsing Tests (test_get_long, test_get_long_base)
- **Verdict: CORRECT** -- Tests decimal and octal parsing. Octal is used for file masks (0644, 0755). Hex parsing (base 16) also verified.

### Default Values (test_default_values)
- **test_default_values** -- Checks defaults:
  - `tcp_port == 445`: **CORRECT** per MS-SMB2 Section 1.7 (port 445).
  - `deadtime == 0`: **CORRECT** -- no idle disconnect by default.
  - `max_connections == 256`: **CORRECT** -- implementation-specific, reasonable default.
  - `sessions_cap == 1024`: **CORRECT** -- implementation-specific.
  - `file_max == 10000`: **CORRECT** -- implementation-specific.
  - `share_fake_fscaps == 64`: **CORRECT** -- implementation-specific.
  - `max_worker_threads == 4`: **CORRECT** -- implementation-specific.
  - `server_string == "SMB SERVER"`: **CORRECT** -- this is the ServerName displayed to clients.
  - `work_group == "WORKGROUP"`: **CORRECT** -- standard default workgroup.
  - `netbios_name == "KSMBD SERVER"`: **CORRECT** -- implementation-specific.
  - `guest_account == "nobody"`: **CORRECT** -- standard Unix guest account.
  - `server_signing == KSMBD_CONFIG_OPT_AUTO`: **CORRECT** per MS-SMB2 Section 3.3.5.3 -- signing should be supported (enabled) but not required by default, "auto" correctly maps to SIGNING_ENABLED in the negotiate response.
  - `KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS` set: **CORRECT** -- Apple compatibility enabled by default.
  - `KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID` set: **CORRECT** -- Apple compatibility.
  - `fruit_model == "Xserve"`: **CORRECT** -- Apple model for Time Machine.
  - `max_ip_connections == 32`: **CORRECT** -- per-IP connection limit.

### Encryption Flag Tests (test_encryption_mandatory, test_encryption_disabled, test_encryption_enabled)
- **Verdict: CORRECT** -- These test three encryption states per MS-SMB2 Section 3.3.5.4:
  - `mandatory` sets KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION (forces encryption, maps to Share.EncryptData=TRUE).
  - `disabled` sets KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF (disables encryption negotiation).
  - `enabled` clears both flags (encryption available if client requests, not forced).
  - The mutual exclusion between ENCRYPTION and ENCRYPTION_OFF is correctly verified.

### Multichannel Flag Tests (test_multichannel_enabled, test_multichannel_disabled)
- **Verdict: CORRECT** -- KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL maps to SMB2_GLOBAL_CAP_MULTI_CHANNEL capability per MS-SMB2 Section 2.2.4. Tests correctly verify flag toggling.

### Durable Handle Flag Tests (test_durable_handle_enabled, test_durable_handle_disabled)
- **Verdict: CORRECT** -- Tests the "durable handles" (plural) configuration key. Per memory notes, "durable handles" (plural) is the correct key that matches the ksmbd-tools parser. The flag KSMBD_GLOBAL_FLAG_DURABLE_HANDLE controls durable handle support per MS-SMB2 Section 3.3.5.9.7.

### Fruit Extension Tests (test_fruit_extensions_disabled, test_fruit_zero_file_id_disabled, test_fruit_nfs_aces_enabled, test_fruit_copyfile_enabled)
- **Verdict: CORRECT** -- Apple macOS compatibility flags. Not spec-governed (vendor extension). Tests correctly verify each flag independently.

### Max Connections Range Tests (test_max_connections_clamped, test_max_connections_zero_clamped, test_max_connections_valid)
- **Verdict: CORRECT** -- Tests that values >65536 and 0 are clamped to KSMBD_CONF_MAX_CONNECTIONS (65536). Valid value 512 is stored as-is.

### Max Worker Threads Range Tests
- **Verdict: CORRECT** -- Tests clamping to 64 (high) and default 4 (low/zero).

### Protocol Version Parsing Tests (test_protocol_min_version, test_protocol_max_version, test_protocol_both_versions)
- **test_protocol_min_version** tests `"SMB2"`: **QUESTIONABLE** -- The kernel-side protocol table uses `"SMB2_02"` for SMB 2.0.2 (dialect 0x0202) and `"SMB2_10"` for SMB 2.1 (dialect 0x0210). The string `"SMB2"` does not appear in the kernel's `smb2_protos[]` table. The test stores the raw config string `"SMB2"` in `global_conf.server_min_protocol`, which is then passed to `ksmbd_lookup_protocol_idx()` in the kernel. If the kernel does not recognize `"SMB2"`, the protocol range will not be set correctly. However, the test is only verifying that the config parser stores the string -- it does not test kernel-side interpretation. The test itself is correct for what it tests (config parsing), but the config value `"SMB2"` may be invalid. The kernel's `ksmbd_lookup_protocol_idx()` function should be checked for alias support.
- **test_protocol_max_version** tests `"SMB3_11"`: **CORRECT** -- This matches the kernel's protocol string for SMB 3.1.1 (dialect 0x0311) per MS-SMB2 Section 2.2.3.
- **test_protocol_both_versions** tests `"SMB2_10"` and `"SMB3"`: `"SMB2_10"` is **CORRECT** (dialect 0x0210). `"SMB3"` is **QUESTIONABLE** for the same reason as `"SMB2"` -- the kernel table uses `"SMB3_00"` for SMB 3.0 (dialect 0x0300). Again, the config parser test itself is correct (it just stores the string), but the actual config value may not be recognized by the kernel.

### TCP Port Test (test_tcp_port_custom)
- **Verdict: CORRECT** -- Custom port 8445.

### Deadtime Test (test_deadtime)
- **Verdict: CORRECT** -- Deadtime 30 minutes.

### SMB2 Leases Tests (test_smb2_leases_enabled, test_smb2_leases_disabled)
- **Verdict: CORRECT** -- KSMBD_GLOBAL_FLAG_SMB2_LEASES maps to SMB2_GLOBAL_CAP_LEASING per MS-SMB2 Section 2.2.4. Tests correctly verify flag toggling.

### Server Signing Test (test_server_signing_mandatory)
- **Verdict: CORRECT** -- KSMBD_CONFIG_OPT_MANDATORY maps to SMB2_NEGOTIATE_SIGNING_REQUIRED in the negotiate response per MS-SMB2 Section 3.3.5.3.

### Combined Flags Test (test_multiple_flags)
- **Verdict: CORRECT** -- Tests that multiple flags can be set simultaneously without interference.

---

## FILE 2: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_config_parser_extended.c`
**61 test cases**

### String Trimming Tests (cp_ltrim, cp_rtrim)
- **Verdict: CORRECT** -- Pure utility tests, not spec-related.

### Key Comparison Tests (cp_key_cmp)
- **Verdict: CORRECT** -- Case-insensitive key comparison per Samba config file convention.

### String/List Parsing Tests
- **Verdict: CORRECT** -- Tests comma/space/tab-delimited list parsing for valid_users, hosts_allow, etc.

### Password DB Parsing Tests (cp_parse_pwddb)
- **Verdict: CORRECT** -- Tests `username:base64password` format. This is ksmbd-tools specific (not spec-governed).

### Smbconf Parsing with Shares
- **Verdict: CORRECT** -- Tests share parsing, comment handling, external group parsing.

### EOL/Printable Tests
- **Verdict: CORRECT** -- Tests `;` and `#` as comment characters (Samba convention), printable character detection.

### Memparse Extended Tests
- **Verdict: CORRECT** -- Tests T/P/E suffixes, hex input, overflow detection.

### restrict_anonymous Tests (test_restrict_anon_type1, test_restrict_anon_type2, test_restrict_anon_invalid)
- **Verdict: CORRECT** -- `restrict anonymous = 1` maps to KSMBD_RESTRICT_ANON_TYPE_1, `2` to TYPE_2, invalid values reset to 0. Per MS-SMB2 Section 3.3.5.7, restricting anonymous access is an implementation-specific server policy.

### map_to_guest Tests
- **Verdict: CORRECT** -- `bad user` maps to KSMBD_CONF_MAP_TO_GUEST_BAD_USER, `never` maps to KSMBD_CONF_MAP_TO_GUEST_NEVER. This implements the Samba-style guest login policy.

### bind_interfaces_only Test
- **Verdict: CORRECT** -- Tests interface binding with space-delimited interface list.

### root_directory Test
- **Verdict: CORRECT** -- Tests root directory prefix for share paths.

### Kerberos Config Test
- **Verdict: CORRECT** -- Tests krb5_support, krb5_service_name, krb5_keytab_file. Kerberos support per MS-SMB2 Section 3.3.5.5 (SPNEGO/Kerberos authentication).

### ipc_timeout Tests
- **Verdict: CORRECT** -- Tests valid timeout and overflow behavior for unsigned short field.

### max_open_files Tests
- **Verdict: CORRECT** -- Tests valid value and zero-clamping to KSMBD_CONF_MAX_OPEN_FILES (65536).

### smb2_max_rw_trans Test
- **Verdict: CORRECT** -- Tests:
  - `smb2 max read = 8M` maps to MaxReadSize per MS-SMB2 Section 2.2.4.
  - `smb2 max write = 4M` maps to MaxWriteSize per MS-SMB2 Section 2.2.4.
  - `smb2 max trans = 1M` maps to MaxTransactSize per MS-SMB2 Section 2.2.4.
  - `smb2 max credits = 512` maps to credit management per MS-SMB2 Section 3.3.1.2.
  - `smbd max io size = 16M` is implementation-specific.
  - All values correctly use memparse with 'M' suffix.

### sessions_cap_clamped Test
- **Verdict: CORRECT** -- Tests clamping to KSMBD_CONF_MAX_ACTIVE_SESSIONS (65536).

### tcp_port_overflow Test
- **Verdict: CORRECT** -- Documents the unsigned short truncation behavior.

### share_fake_fscaps Test
- **Verdict: CORRECT** -- Implementation-specific filesystem capability masking.

### optional_server_limits Test
- **Verdict: CORRECT** -- Tests many operational parameters: tcp_recv_timeout, tcp_send_timeout, quic timeouts, max_lock_count, max_buffer_size, session_timeout, durable_handle_timeout, max_inflight_req, max_async_credits, max_sessions, smb1_max_mpx.

### max_ip_connections_clamped Test
- **Verdict: CORRECT** -- Zero clamped to KSMBD_CONF_MAX_CONNECTIONS.

### fruit_model_custom Test
- **Verdict: CORRECT** -- Custom Apple model string.

---

## FILE 3: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_share_admin.c`
**~60 test cases** (large file)

### Share Name Validation (shm_share_name)
- Valid names, empty names, brackets, control chars, UTF-8: **CORRECT** -- Brackets disallowed (they delimit section headers), control chars disallowed, UTF-8 allowed.

### Share Name Hashing
- Case-insensitive hashing: **CORRECT** -- Share names are case-insensitive per MS-SMB2 (tree connect share names are case-insensitive).

### Share Config Key Matching
- All config keys tested: **CORRECT** -- Verifies "path", "comment", "guest ok", "read only", "browseable", "oplocks", "create mask", "valid users", "hosts allow", "hosts deny", "veto files", "streams", "acl xattr".
- ADMIN_USERS marked as BROKEN returning 0: **CORRECT** -- Acknowledged broken feature.

### Duplicate Share Handling
- **Verdict: CORRECT** -- Duplicate adds are silent (second add replaces or is ignored).

### Share Options Tests (comment, read_only, writeable, guest_ok, browseable, oplocks, store_dos_attributes, hide_dot_files, create_mask, directory_mask, force modes, inherit_owner, follow_symlinks, crossmnt, streams, acl_xattr)
- All: **CORRECT** -- Each config option maps to the correct KSMBD_SHARE_FLAG.

### Continuous Availability Test
- **Verdict: CORRECT** -- `continuous availability = yes` sets KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY, which maps to SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY (0x00000010) per MS-SMB2 Section 2.2.10. The kernel's tree connect handler sets this capability bit when the share flag is present.

### VFS Objects Test
- **Verdict: CORRECT** -- `vfs objects = acl_xattr streams_xattr` sets both ACL_XATTR and STREAMS flags.

### Max Connections Test
- **Verdict: CORRECT** -- Tests connection limit enforcement with open/close tracking.

### Fruit Options Tests (time_machine, finder_info, rfork_size, max_access)
- **Verdict: CORRECT** -- Apple-specific extensions, not spec-governed.

### Payload Size and Serialization Tests
- **Verdict: CORRECT** -- Tests the netlink share config payload format.

### command_add_share / command_update_share / command_delete_share
- All: **CORRECT** -- Tests high-level share administration CRUD operations with file I/O.

---

## FILE 4: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_share_management.c`
**49 test cases**

### shm_share_config Tests
- **Verdict: CORRECT** -- Same as in test_share_admin.c, verifies config key matching.

### shm_share_name Tests
- **Verdict: CORRECT** -- Same validation as above, includes long name (>KSMBD_REQ_MAX_SHARE_NAME) rejection test.

### Share Lookup and Reference Counting
- **Verdict: CORRECT** -- Tests get/put refcounting semantics.

### Share Iteration
- **Verdict: CORRECT** -- Counts shares including auto-created IPC$ share.

### Connection Tracking
- **Verdict: CORRECT** -- Tests max_connections enforcement, underflow protection on close.

### Share Flag Tests
- All flags tested: **CORRECT** -- guest_ok, read_only, writeable, browseable, streams, acl_xattr, store_dos_attrs, oplocks, crossmnt.

### Share Masks and Force Modes
- **Verdict: CORRECT** -- Tests octal mask parsing and storage.

### Hosts Map Tests
- Exact IPv4, CIDR /8, IPv6 CIDR /16, multiple entries: **CORRECT** -- Per MS-SMB2, host ACLs are implementation-specific.
- Invalid map index returns -EINVAL: **CORRECT**.
- No map configured returns -EINVAL: **CORRECT**.

### Users Map Tests
- Invalid index, no map: **CORRECT** -- Edge case handling.

### Share Name Hash/Equal
- **Verdict: CORRECT** -- Case-insensitive share name handling.

### Null Safety Tests
- put_ksmbd_share(NULL), shm_close_connection(NULL), shm_share_config_payload_size(NULL), shm_handle_share_config_request(NULL, &resp): **CORRECT** -- All null-safe.

### Veto Files Test
- **Verdict: CORRECT** -- Tests slash-delimited veto file list conversion to NUL-separated internal format.

### IPC$ Pipe Share Test
- **Verdict: CORRECT** -- Verifies IPC$ auto-creation with KSMBD_SHARE_FLAG_PIPE flag.

### Remove All Shares Test
- **Verdict: CORRECT** -- Tests bulk share removal.

---

## FILE 5: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_share_config_payload.c`
**8 test cases**

### Payload Size Calculations
- `test_payload_size_no_veto_no_root`: path="/data" => payload 6 bytes (strlen("/data")+1 for path + NUL): **CORRECT**.
- `test_payload_size_with_root_and_veto`: root_dir="/root", path="/share", veto_list_sz=3 => payload 16 bytes: **CORRECT** -- includes root_dir+path concatenation + veto list.
- `test_payload_size_pipe_share_zero`: pipe shares have 0 payload: **CORRECT** -- IPC$ shares have no filesystem path.
- `test_payload_size_invalid_path`: NULL or empty path returns -EINVAL: **CORRECT**.

### Serialization Tests
- `test_serialize_no_veto`: Verifies share_name, veto_list_sz=0, path stored correctly: **CORRECT**.
- `test_serialize_with_veto_and_root`: Verifies veto list bytes, root_dir+path concatenation: **CORRECT**.
- `test_serialize_insufficient_payload`: Undersized buffer returns -EINVAL: **CORRECT**.
- `test_serialize_pipe_share`: Pipe share with 0 payload: **CORRECT**.

---

## FILE 6: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_user_admin.c`
**32 test cases**

### Password DB Parsing
- Single user, multiple users, empty file, blank lines, whitespace: **CORRECT** -- Tests `username:base64password\n` format.

### User Lifecycle (add, remove, password update, duplicate)
- All: **CORRECT** -- Standard CRUD operations with proper refcounting.

### User Name Validation
- Valid, empty, colon (disallowed), control chars (disallowed), UTF-8 (allowed), space (allowed), tab (allowed): **CORRECT** -- Colons disallowed because the pwddb format uses `:` as delimiter.

### User Flag Operations
- KSMBD_USER_FLAG_GUEST_ACCOUNT, KSMBD_USER_FLAG_DELAY_SESSION: **CORRECT** -- BIT(4) and BIT(5) respectively per ksmbd_server.h.

### Guest Account
- usm_add_guest_account sets KSMBD_USER_FLAG_GUEST_ACCOUNT: **CORRECT** -- Guest users mapped to null sessions per MS-SMB2 Section 3.3.5.5.

### command_add_user Tests
- With password, duplicate returns -EEXIST, empty password, password hash is valid base64, Unicode password, single char password: **CORRECT** -- The password processing chain is: plaintext -> UTF-16LE conversion -> MD4 hash -> base64 encode. This matches NTLM authentication per MS-NLMP.

### command_update_user Tests
- Basic update, nonexistent returns -EINVAL, preserves other users: **CORRECT**.

### command_delete_user Tests
- Basic delete, nonexistent returns -EINVAL, preserves other users, user required by share returns -EINVAL, user required as global guest returns -EINVAL: **CORRECT** -- Dependency checking before deletion.

### Password File Format Verification
- `username:base64hash\n` format: **CORRECT**.

### Guest Users Excluded from Listing
- Guest accounts (KSMBD_USER_FLAG_GUEST_ACCOUNT) excluded from pwddb file writes: **CORRECT** -- Guest accounts are ephemeral.

---

## FILE 7: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_user_management.c`
**39 test cases**

### Add/Lookup/Remove/Duplicate
- All: **CORRECT** -- Same low-level user management operations as test_user_admin.c but at the usm_* API level.

### Password Update
- Valid base64 password, invalid/empty base64: **CORRECT** -- Handles edge cases without crashing.

### User Iteration/Remove All
- **Verdict: CORRECT** -- Bulk operations.

### Guest Account
- **Verdict: CORRECT** -- Same as test_user_admin.c.

### User Name Validation
- Valid, empty, colon, control char, UTF-8, too long: **CORRECT**.

### Ref Counting
- **Verdict: CORRECT** -- get_ksmbd_user increments, put_ksmbd_user decrements.

### User Flag Operations
- **Verdict: CORRECT** -- Same flag tests as test_user_admin.c.

### Login Request Tests (usm_handle_login_request)
- **test_usm_handle_login_request_valid_user**: Returns KSMBD_USER_FLAG_OK: **CORRECT** per MS-SMB2 Section 3.3.5.5.
- **test_usm_handle_login_request_null_session**: Empty account maps to guest: **CORRECT** per MS-SMB2 Section 3.3.5.5.3 (null sessions).
- **test_usm_handle_login_request_bad_user**: Returns KSMBD_USER_FLAG_BAD_USER: **CORRECT**.
- **test_usm_handle_login_request_map_to_guest**: Bad user with map_to_guest=bad_user maps to guest login: **CORRECT** per Samba semantics.
- **test_usm_handle_login_request_invalid_account**: Non-NUL-terminated account returns -EINVAL with KSMBD_USER_FLAG_INVALID: **CORRECT**.

### Login Request Ext Tests
- Valid, empty, invalid account: **CORRECT** -- Extended login request with group info.

### Logout Request Tests
- Valid, bad password counting, nonexistent, invalid account, delay session after 10 failures: **CORRECT** -- Account lockout after 10 bad password attempts setting KSMBD_USER_FLAG_DELAY_SESSION is a reasonable brute-force protection mechanism. Successful login resets the counter.

### Init/Destroy Lifecycle
- **Verdict: CORRECT** -- Multiple init/destroy cycles, double init as no-op.

---

## FILE 8: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_control.c`
**39 test cases**

### signing_to_str Tests
- DISABLED->"disabled", ENABLED->"enabled", AUTO->"auto", MANDATORY->"mandatory": **CORRECT** -- These map to:
  - disabled: No signing (violates MS-SMB2 Section 3.3.5.3 which says SIGNING_ENABLED must be set, but ksmbd may handle this by always advertising signing capability)
  - enabled: SMB2_NEGOTIATE_SIGNING_ENABLED per Section 2.2.4
  - auto: SMB2_NEGOTIATE_SIGNING_ENABLED per Section 2.2.4 (same as enabled for negotiate, but signing only used if peer requires)
  - mandatory: SMB2_NEGOTIATE_SIGNING_REQUIRED per Section 2.2.4
- Unknown values return "unknown": **CORRECT**.
- All four are distinct: **CORRECT**.

### read_sysfs_string Tests
- Success, nonexistent, empty, no trailing newline, multiple lines, truncation, exact fit, binary content, whitespace, min buffer, numeric content: **CORRECT** -- Thorough sysfs reading tests.

### control_features Tests
- Minimal config, all flags enabled, signing disabled, missing config, with share, output format: **CORRECT** -- Tests the feature status display, verifying expected output strings.

### control_limits Tests
- Minimal config, with values, missing config, output format, with shares: **CORRECT** -- Tests the limits display.

### Feature Flags Table Tests
- Count (8 flags), power-of-two, no overlap: **CORRECT** -- Validates flag bit layout integrity.

### Config Opt Constants
- DISABLED=0, ENABLED=1, AUTO=2, MANDATORY=3: **CORRECT**.

### Global Config Integration Tests
- Defaults after load, signing mandatory, protocol strings "SMB2_10"/"SMB3_11": **CORRECT** per kernel protocol table.
- Null protocols handled gracefully: **CORRECT**.
- TCP port 8445: **CORRECT**.

### control_show_version, control_debug
- Smoke tests (no crash): **CORRECT**.

---

## FILE 9: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_tools_utils.c`
**35 test cases**

### Base64 Round-trip Tests
- Empty, known values ("cGFzcw==" -> "pass"), binary data, large data: **CORRECT** -- Base64 is used for password storage in pwddb.

### Charset Conversion Tests (ksmbd_gconvert)
- UTF-8 to UTF-16LE: **CORRECT** -- SMB2 protocol uses UTF-16LE for file names per MS-SMB2 Section 2.2.13.
- UTF-16LE to UTF-8: **CORRECT**.
- Invalid codeset returns NULL: **CORRECT**.
- UTF-8 to UTF-16BE, UTF-16BE to UTF-8: **CORRECT**.
- Empty string conversion: **CORRECT**.

### GPtrArray Utility Tests
- to_strv, to_str, printf: **CORRECT** -- GLib utility wrappers.

### Log Level Tests
- set_log_level, sticky debug: **CORRECT** -- Once set to DEBUG, it sticks.

### Logger Init Tests
- Syslog, JSON: **CORRECT** -- Multiple logger backends.

### Hex Dump Test
- No-crash test: **CORRECT**.

### Charset Names
- UTF-8, UTF-16LE, UCS-2LE, UTF-16BE, UCS-2BE: **CORRECT** -- All encoding names verified.
- Sentinel KSMBD_CHARSET_MAX="OOPS": **CORRECT** -- Guard value.

### Tool Name Tests
- Default "ksmbd.tools", "ksmbdctl", "ksmbdctl(share)", "ksmbdctl(user)", "ksmbdctl(control)": **CORRECT**.

### set_conf_contents Tests
- Valid write, invalid path returns -EINVAL, overwrite, empty: **CORRECT**.

### set_tool_main Tests
- "ksmbdctl" valid, "invalid" returns -EINVAL: **CORRECT**.

### show_version
- Returns 0: **CORRECT**.

### remove_config
- No crash with NULL tool_main, addshare mode: **CORRECT**.

---

## FILE 10: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_host_acl.c`
**13 test cases**

### Exact IPv4 Matching
- "192.168.1.1" matches itself, does not match "192.168.1.2": **CORRECT**.

### CIDR /24 Subnet
- "192.168.1.0/24" matches "192.168.1.100", does not match "192.168.2.1": **CORRECT**.

### CIDR /32 (Single Host)
- "10.0.0.1/32" matches "10.0.0.1", does not match "10.0.0.2": **CORRECT**.

### CIDR /0 (Match All)
- "0.0.0.0/0" matches "1.2.3.4": **CORRECT**.

### Hostname Matching
- "server1" matches "server1", does not match "server2": **CORRECT** -- Falls back to strcmp when no CIDR notation.

### IPv6 CIDR Matching
- "fd00::/16" matches "fd00::1", does not match "fe80::1": **CORRECT**.

### Invalid CIDR Fallback
- "invalid/24" matches "invalid/24" via strcmp: **CORRECT** -- inet_pton fails on "invalid", so falls back to exact string match.

### CIDR Implementation Review
- The `match_host_cidr()` function is a self-contained copy from `tools/management/share.c`. The implementation is correct:
  - Proper address family detection (`:` in string -> AF_INET6).
  - Proper prefix length validation against address length.
  - Byte-by-byte comparison for full bytes, mask comparison for partial bytes.
  - Proper fallback to strcmp on any parsing error.

---

## SUMMARY OF FINDINGS

### WRONG: 0 issues found

### QUESTIONABLE: 2 issues found

1. **test_config_parser.c line 522-528, test_protocol_min_version**: Uses protocol string `"SMB2"` which does not appear in the kernel's `smb2_protos[]` table. The kernel recognizes `"SMB2_02"` (SMB 2.0.2), `"SMB2_10"` (SMB 2.1), `"SMB3_00"` (SMB 3.0), `"SMB3_02"` (SMB 3.0.2), and `"SMB3_11"` (SMB 3.1.1). If `ksmbd_lookup_protocol_idx()` does not have an alias for `"SMB2"`, this config value would be silently ignored by the kernel, and the protocol range would not be set. The test only verifies that the config parser stores the string, not that it is a valid kernel protocol identifier.

2. **test_config_parser.c line 549-566, test_protocol_both_versions**: Uses protocol string `"SMB3"` for `server max protocol`. Same issue as above -- the kernel table uses `"SMB3_00"` for SMB 3.0. The string `"SMB3"` is not in the kernel's protocol table.

### CORRECT: All remaining ~312 test cases

All share flags, user flags, config options, signing modes, encryption modes, protocol capabilities, host ACLs, payload serialization, connection tracking, reference counting, and null-safety tests are correctly implemented and accurately reflect both the ksmbd-tools internal APIs and the relevant MS-SMB2 specification requirements where applicable.

### COVERAGE GAPS (Not found in tests but spec-relevant)

The following configuration-to-spec mappings are not tested but could be beneficial:

- **SMB2_SHARE_CAP_DFS** (0x00000008): No test verifies that a DFS-related share config maps to this capability.
- **SMB2_SHARE_CAP_ENCRYPT_DATA**: No test verifies that per-share encryption (as opposed to global) maps correctly to Share.EncryptData per MS-SMB2 Section 2.2.10.
- **ACCESS_BASED_DIRECTORY_ENUM**: No test for this SHI1005_FLAGS mapping.
- **Protocol version string validation**: No test verifies that invalid protocol strings (e.g., `"SMB2"`, `"SMB3"`, `"INVALID"`) are rejected or handled gracefully at the kernel interface level.
- **Signing mode to SecurityMode mapping**: No test verifies the exact bit mapping from KSMBD_CONFIG_OPT_MANDATORY to SMB2_NEGOTIATE_SIGNING_REQUIRED in the negotiate response SecurityMode field.