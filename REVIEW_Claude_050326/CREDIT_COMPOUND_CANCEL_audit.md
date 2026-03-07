# Credit Compound Cancel Audit

Agent ID: abbfe45b3f1c49c9c

Only one enum value defined, and it's 0x0. The test and code both use 0x2 which contradicts the spec. This is WRONG.

Now let me look at the StructureSize for the notification. The spec says (line 10288-10289): "StructureSize (2 bytes): The server MUST set this to the size of the SMB2_SERVER_TO_CLIENT_NOTIFICATION structure." And the example (line 29868) shows 0x12 = 18.

The structure per the wire format has:
- StructureSize (2 bytes)
- Reserved (2 bytes)
- NotificationType (4 bytes)
- Notification (variable)

For SmbNotifySessionClosed, the Notification field is the SMB2_NOTIFY_SESSION_CLOSED struct which has:
- Reserved (4 bytes)

Total body (not counting header): 2+2+4+4 = 12 bytes. But the example says 18. The discrepancy of 6 bytes is puzzling. Let me check if maybe there's extra padding or I'm miscounting.

Actually, maybe the StructureSize in the spec example includes the SMB2_SERVER_TO_CLIENT_NOTIFICATION structure but was interpreted differently. Or maybe the spec trace has a different version of the structure. In any case, the test uses 4, the spec example uses 18, and the minimum size based on the structure definition is 12. All three disagree.

The test value of 4 (which matches only StructureSize + Reserved = 4 bytes) seems to follow the pattern of some other SMB2 structures where StructureSize reflects just the fixed non-variable part. But that doesn't match this structure either, since the fixed part includes NotificationType (4 bytes more). And 4 clearly contradicts the spec example value of 18.

Let me now produce the final audit report.

---

Here is the comprehensive audit report.

## Audit Summary

**Files requested**: 6
**Files found**: 2 (the following 4 files do not exist in the repository)
- `test/ksmbd_test_compound.c` -- NOT FOUND
- `test/ksmbd_test_cancel.c` -- NOT FOUND
- `test/ksmbd_test_error_misc.c` -- NOT FOUND
- `test/ksmbd_test_async.c` -- NOT FOUND

**Files audited**:
1. `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_misc_cmds.c` -- 34 tests
2. `/home/ezechiel203/ksmbd/test/ksmbd_test_credit.c` -- 7 tests

**Total tests audited: 41**
**CORRECT: 37**
**WRONG: 3**
**QUESTIONABLE: 1**

---

## WRONG Findings

### WRONG-1: `test_notify_session_closed_type` (line 174, `ksmbd_test_smb2_misc_cmds.c`)

**Test expectation**: `SMB2_NOTIFY_SESSION_CLOSED == 0x00000002`

**Spec says**: MS-SMB2 section 2.2.44.1 (line 10300) defines the `NotificationType` enum value as:
> `SmbNotifySessionClosed (0x0)`

And the spec example in section 4.11 (line 29870) shows:
> `NotificationType: 0x0 (SmbNotifySessionsClosed)`

The test expects `0x00000002` for the `NotificationType` field value, but the spec unambiguously defines `SmbNotifySessionClosed` as `0x0`. The underlying constant definition at `/home/ezechiel203/ksmbd/src/include/protocol/smb2pdu.h:1502` is also wrong:
```c
#define SMB2_NOTIFY_SESSION_CLOSED	cpu_to_le32(0x00000002)
```

**Spec reference**: MS-SMB2 section 2.2.44.1, table at line 10298-10302; section 4.11 example at line 29870.

---

### WRONG-2: `test_notification_struct_layout` (line 184, `ksmbd_test_smb2_misc_cmds.c`)

**Test expectation**: `notif.StructureSize == 4`

**Spec says**: MS-SMB2 section 2.2.44.1 (line 10288-10289):
> "StructureSize (2 bytes): The server MUST set this to the size of the SMB2_SERVER_TO_CLIENT_NOTIFICATION structure."

The spec example in section 4.11 (line 29868) shows:
> `StructureSize: 0x12` (18 decimal)

The `SMB2_SERVER_TO_CLIENT_NOTIFICATION` structure has fixed fields: StructureSize(2) + Reserved(2) + NotificationType(4) = 8 bytes minimum (excluding the variable Notification payload), or 12 bytes with the `SMB2_NOTIFY_SESSION_CLOSED` payload (Reserved 4 bytes). The test sets StructureSize to 4, which only accounts for StructureSize + Reserved and contradicts both the spec definition and the spec's own example trace.

**Spec reference**: MS-SMB2 section 2.2.44.1 line 10288-10289; section 4.11 example at line 29868.

---

### WRONG-3: `test_credit_charge_zero` (line 104, `ksmbd_test_credit.c`)

**Test expectation**: Credit charge for (0, 0) payload = 0

**Spec says**: MS-SMB2 section 3.1.5.2 (line 10729) defines the formula:
> `CreditCharge = (max(SendPayloadSize, Expected ResponsePayloadSize) - 1) / 65536 + 1`

With `max = 0`, this formula yields `(0 - 1) / 65536 + 1`. Using C integer division (truncation toward zero): `(-1) / 65536 = 0`, then `0 + 1 = 1`. The spec formula always produces a minimum of 1 credit.

The test uses `DIV_ROUND_UP(0, 65536)` which equals 0. The test comment acknowledges "in the actual kernel code, credit_charge is floored to 1" but still asserts 0 for the helper function. Since the test purports to replicate the spec formula (line 28-29: "This replicates the formula used in smb2_validate_credit_charge()"), and the spec formula yields 1 (not 0), the test expectation is wrong.

**Spec reference**: MS-SMB2 section 3.1.5.2, line 10729.

---

## QUESTIONABLE Findings

### Q-1: `test_notification_header_flags` (line 202, `ksmbd_test_smb2_misc_cmds.c`)

**Test expectation**: Notification header has `SMB2_FLAGS_SERVER_TO_REDIR` set and `MessageId = 0xFFFFFFFFFFFFFFFF`.

**Spec says**: MS-SMB2 section 3.2.5.20 (line 17117):
> "Like an SMB2 OPLOCK_BREAK Notification, the MessageID should be set to 0xFFFFFFFFFFFFFFFF."

The use of "should" (lowercase) rather than "MUST" makes this a recommendation, not a requirement. Additionally, the test also asserts `SMB2_NOTIFY_SESSION_CLOSED` as the Command value and the `SMB2_FLAGS_SERVER_TO_REDIR` flag. While these are reasonable expectations, the spec section on the header for notifications doesn't explicitly mandate `SMB2_FLAGS_SERVER_TO_REDIR` for this specific notification type (though it is standard for server-initiated messages). The MessageId assertion is likely correct but the spec language is "should" (informative) rather than "MUST" (normative).

This test is classified as QUESTIONABLE because it relies on a "should" recommendation rather than a normative "MUST" for the MessageId, and the flags are inferred from convention rather than an explicit spec statement for this notification type.

**Spec reference**: MS-SMB2 section 3.2.5.20, line 17117.

---

## CORRECT Tests (summary)

All other 37 tests are CORRECT per the spec:

**`ksmbd_test_smb2_misc_cmds.c`** (31 correct):
- Echo response StructureSize = 4 (MS-SMB2 section 2.2.29, line 7762)
- Echo response Reserved = 0 (MS-SMB2 section 2.2.29, line 7765)
- Echo response sizeof (header + 4 bytes body)
- Close request StructureSize = 24 (MS-SMB2 section 2.2.15, line 6493)
- Close response StructureSize = 60 (MS-SMB2 section 2.2.16, line 6574)
- `SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB = 0x0001` (MS-SMB2 section 2.2.15, line 6501-6502)
- Close response without POSTQUERY zeroes fields (MS-SMB2 section 2.2.16, lines 6601-6626)
- Close response with POSTQUERY has valid values (MS-SMB2 section 2.2.16)
- `SMB2_SERVER_TO_CLIENT_NOTIFICATION = 0x0013` command code (MS-SMB2 section 2.2.1, line 2154)
- Notification session ID carries session ID (standard header field)
- Oplock break StructureSize 24 (MS-SMB2 section 2.2.23.1, line 7139)
- Lease break ack/response StructureSize 36 (MS-SMB2 section 2.2.24.2 line 7387, section 2.2.25.2 line 7528)
- Oplock/lease break dispatch by StructureSize
- Invalid StructureSize (neither 24 nor 36)
- SMB2 header StructureSize = 64 (MS-SMB2 section 2.2.1, line 2078)
- `SMB2_PROTO_NUMBER = 0x424D53FE` (MS-SMB2 section 2.2.1, line 2075)
- All 13 `check_lease_state` tests correctly verify subset semantics per MS-SMB2 section 3.3.5.22.2 (line 26143): "If LeaseState is not a subset of Lease.BreakToLeaseState, the server MUST fail the request"

**`ksmbd_test_credit.c`** (6 correct out of 7):
- 1 credit for <= 64KB (matches spec formula)
- 2 credits for 128KB (matches `(131072-1)/65536+1 = 2`)
- 4 credits for 256KB (matches `(262144-1)/65536+1 = 4`)
- 2 credits for 65537 bytes (matches `(65537-1)/65536+1 = 2`)
- 3 credits when response is 192KB (matches `(196608-1)/65536+1 = 3`)
- 1 credit for exactly 64KB, 128 credits for 8MB (both match spec)