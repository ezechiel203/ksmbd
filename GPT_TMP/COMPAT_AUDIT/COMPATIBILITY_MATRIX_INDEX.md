# ksmbd Compatibility Matrix Index

Date: 2026-03-07

These files together are the expanded compatibility program baseline.

## Master surface matrix

- [COMPLIANCE_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/COMPLIANCE_MATRIX.csv)
- [COMPLIANCE_MATRIX.md](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/COMPLIANCE_MATRIX.md)

## Contract-level matrices

- [NEGOTIATE_CONTEXT_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/NEGOTIATE_CONTEXT_MATRIX.csv)
  Covers negotiate-request and negotiate-response contract rules, mandatory contexts, duplicate handling, and known non-compliant negotiate features.

- [SMB2_PDU_FIELD_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/SMB2_PDU_FIELD_MATRIX.csv)
  Covers field-by-field SMB2/SMB3 request validation now visible in the live code: offsets, alignments, enum ranges, replay gates, compound constraints, and encrypted-wrapper checks.

- [SMB1_TRANSACTION_SUBCOMMAND_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/SMB1_TRANSACTION_SUBCOMMAND_MATRIX.csv)
  Covers SMB1 `SMB_COM_TRANSACTION`, `TRANS2`, and `NT_TRANSACT` subcommand families with implemented, unsupported, and stubbed branches called out explicitly.

- [SMB1_ANDX_CHAIN_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/SMB1_ANDX_CHAIN_MATRIX.csv)
  Covers SMB1 AndX request-walk and response-chaining rules, including forward-progress guards, chain termination, and representative response paths.

- [SMB1_FRAGMENTATION_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/SMB1_FRAGMENTATION_MATRIX.csv)
  Covers what ksmbd really does today for SMB1 transaction-family fragmentation and continuation handling, including the still-missing secondary paths.

- [QUERY_SET_INFO_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/QUERY_SET_INFO_MATRIX.csv)
  Covers SMB2/SMB3 query-directory, query-info, and set-info classes as first-class compliance rows.

- [SMB2_CREATE_CONTEXT_WIRE_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/SMB2_CREATE_CONTEXT_WIRE_MATRIX.csv)
  Covers SMB2 create-context request parsing and response packing at the wire-layout level for durable, lease, POSIX, AAPL, maximal-access, and disk-id contexts.

- [FSCTL_CONTRACT_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/FSCTL_CONTRACT_MATRIX.csv)
  Covers all registered FSCTL handlers across core and extension modules with contract focus per handler.

- [RPC_WIRE_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/RPC_WIRE_MATRIX.csv)
  Covers DCE/RPC packet mechanics, bind and alter-context behavior, pipe lifecycle, and exposed interface/opnum coverage.

- [APPLE_AAPL_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/APPLE_AAPL_MATRIX.csv)
  Covers Apple AAPL create-context semantics, capability bits, AFP_AfpInfo behavior, and missing Apple features.

- [TRANSPORT_STATE_MACHINE_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/TRANSPORT_STATE_MACHINE_MATRIX.csv)
  Covers RDMA credit and transform semantics plus QUIC transport states and transitions.

- [LEASE_DURABLE_REPLAY_SCENARIO_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/LEASE_DURABLE_REPLAY_SCENARIO_MATRIX.csv)
  Covers stateful lease, dirlease, durable-v1, durable-v2, resilient, replay, notify, and multichannel-adjacent scenarios with current local evidence attached.

- [INTEROP_RESULT_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/INTEROP_RESULT_MATRIX.csv)
  Tracks what is actually proven today across SMB1, SMB2/SMB3, QUIC, RDMA, Apple, RPC, DFS, VSS, reparse, quota, and reserved virtual-disk areas.

- [SPEC_PARAGRAPH_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/SPEC_PARAGRAPH_MATRIX.csv)
  Maps the highest-risk protocol behaviors to concrete spec sections or in-tree spec-comment anchors so fixes can be checked against a stated contract.

- [PROOF_MAPPING_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/PROOF_MAPPING_MATRIX.csv)
  Tracks which compatibility claims have only implementation evidence, which have KUnit-visible helpers, which have harnesses, and which have real failing or passing artifacts.

- [STATUS_CODE_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/STATUS_CODE_MATRIX.csv)
  Tracks high-risk NTSTATUS and wire-status behavior that clients depend on for fallback and interoperability.

## Remaining gaps before a true “100% compatibility” claim

- Full request/response field tables for every remaining SMB1 and SMB2/3 command, not just the currently visible high-risk validations and create-context/AndX families
- Exact paragraph-level spec mapping for every row, not just the currently mapped high-risk behaviors
- Automated proof mapping for every row, not just the current high-risk, scenario, and transport sets
- Real Windows, Samba, macOS, RDMA, and QUIC execution results instead of category-only placeholders
- Packet captures and parser-level conformance checks proving the documented SMB1 AndX, SMB1 fragmentation, and SMB2 create-context wire layouts match real clients
