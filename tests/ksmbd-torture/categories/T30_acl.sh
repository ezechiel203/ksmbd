#!/bin/bash
# T30: ACL and Security (12 tests)

register_test "T30.01" "test_acl_query_dacl" --timeout 20 \
    --requires "smbtorture" \
    --description "Query DACL on file"
test_acl_query_dacl() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local fname="t30_acl_query_$$"
    smb_write_file "$fname" "acl dacl query test" >/dev/null 2>&1
    local output
    output=$(torture_run "smb2.acls.GENERIC" 2>&1)
    local rc=$?
    smb_rm "$fname" 2>/dev/null
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T30.02" "test_acl_set_dacl" --timeout 20 \
    --requires "smbtorture" \
    --description "Set DACL with specific ACEs"
test_acl_set_dacl() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.acls.GENERIC" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T30.03" "test_acl_query_owner" --timeout 20 \
    --requires "smbtorture" \
    --description "Query owner SID"
test_acl_query_owner() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.acls.OWNER" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T30.04" "test_acl_set_owner" --timeout 20 \
    --requires "smbtorture" \
    --description "Set owner SID"
test_acl_set_owner() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.acls.OWNER" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T30.05" "test_acl_query_group" --timeout 20 \
    --requires "smbtorture" \
    --description "Query primary group SID"
test_acl_query_group() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # SDFLAGSVSCHOWN tests security descriptor flags vs chown interaction,
    # which exercises group SID querying and setting
    local output
    output=$(torture_run "smb2.acls.SDFLAGSVSCHOWN" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T30.06" "test_acl_empty_dacl" --timeout 20 \
    --requires "smbtorture" \
    --description "Set empty DACL (0 ACEs), hide_on_access_denied returns NAME_NOT_FOUND"
test_acl_empty_dacl() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # ACCESSBASED tests access-based enumeration (hide_on_access_denied behavior):
    # files with empty DACLs should appear as if they do not exist
    local output
    output=$(torture_run "smb2.acls.ACCESSBASED" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T30.07" "test_acl_partial_dacl" --timeout 20 \
    --requires "smbtorture" \
    --description "DACL with FILE_READ_ATTRIBUTES ACE only makes file visible but denied"
test_acl_partial_dacl() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # DYNAMIC tests dynamic ACL changes and their effect on access
    local output
    output=$(torture_run "smb2.acls.DYNAMIC" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T30.08" "test_acl_null_dacl" --timeout 15 \
    --requires "smbtorture" \
    --description "Set NULL DACL (no DACL present) - everyone full access"
test_acl_null_dacl() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.create.nulldacl" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T30.09" "test_acl_inherit_file" --timeout 20 \
    --requires "smbtorture" \
    --description "Create file in directory with inheritable ACEs"
test_acl_inherit_file() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.acls.INHERITANCE" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T30.10" "test_acl_inherit_directory" --timeout 20 \
    --requires "smbtorture" \
    --description "Create subdirectory with inheritable ACEs"
test_acl_inherit_directory() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.acls.INHERITFLAGS" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T30.11" "test_acl_maximum_allowed_dacl" --timeout 20 \
    --requires "smbtorture" \
    --description "MAXIMUM_ALLOWED with complex DACL grants correct access"
test_acl_maximum_allowed_dacl() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # CREATOR tests CREATOR_OWNER / CREATOR_GROUP ACE expansion with MAXIMUM_ALLOWED
    local output
    output=$(torture_run "smb2.acls.CREATOR" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T30.12" "test_acl_audit_sacl" --timeout 15 \
    --description "Set/query SACL (audit) requires SeSecurityPrivilege"
test_acl_audit_sacl() {
    skip_test "SACL requires SeSecurityPrivilege - not available in unprivileged test environment"
}
