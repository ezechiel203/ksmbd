# KSMBD Full RFC-Compliant QUIC Test Plan

## Goal

Enable end-to-end SMB over QUIC testing with real QUIC/TLS semantics (not TCP emulation), with deterministic validation on VM0-VM2.

## Scope Baseline

This repo currently supports a kernel-side QUIC bridge endpoint via abstract unix socket `@ksmbd-quic` (`src/transport/transport_quic.c`).

To reach full compatibility, we need:

1. A real userspace QUIC proxy (RFC 9000/9001/9002)
2. mTLS enforcement and policy mapping for SMB clients
3. Interop validation against real SMB-over-QUIC clients (Windows)

## Architecture Target

Client (Windows SMB over QUIC)
  -> UDP/443 QUIC + TLS 1.3
  -> userspace QUIC proxy daemon
  -> unix abstract socket `@ksmbd-quic`
  -> kernel ksmbd QUIC transport

## Required Components

### Proxy implementation

- Preferred stack: `msquic`
- Alternative stacks: `quiche`, `ngtcp2`
- Requirements:
  - QUIC v1 transport + recovery
  - TLS 1.3 handshake + ALPN handling
  - stream framing suitable for SMB payload forwarding

### PKI / TLS materials

- Root CA + issuing CA
- Server cert for QUIC listener (SAN matches endpoint)
- Client certs (for mutual TLS)
- Revocation strategy (CRL/OCSP policy)

### Host/VM network setup

- UDP/443 forward + allow rules
- TCP/443 optional only for diagnostics/proxy control plane
- Preserve existing SMB/TCP ports for A/B comparison

## Protocol Contract Between Proxy and Kernel

### Current contract

- On accepted proxy<->kernel socket connection, send `struct ksmbd_quic_conn_info`
- Then forward decrypted SMB stream bytes bidirectionally

### Must be hardened for production-like testing

- Verify proxy peer credentials (`SO_PEERCRED`) on unix socket
- Enforce strict validation of proxy-provided source metadata
- Validate flags (`TLS_VERIFIED`, early data handling)

## Validation Matrix

### Interop

1. Windows client connect over QUIC (UDP/443)
2. Cert validation + client cert auth
3. Browse/list shares
4. Open/read/write/delete under encryption

### RFC behavior

1. Handshake timeout handling
2. Loss/reorder resilience
3. Idle timeout + re-handshake behavior
4. Stream reset/close semantics

### Stress

1. Parallel clients x N per VM
2. Long-run mixed IO + browse loops
3. Proxy restart behavior and recovery
4. dmesg/journal regression checks (no lockups/UAF/Oops)

## Implementation Phases

### Phase 1: Real proxy skeleton

- Replace emulator with real QUIC listener on UDP/443
- Implement accepted-connection mapping to kernel bridge
- Add structured logs and connection IDs

### Phase 2: Security completion

- mTLS policy + cert lifecycle
- unix socket peer-auth in kernel transport
- strict metadata trust boundary checks

### Phase 3: Interop and endurance

- Windows interop scripts
- automated matrix and soak tests
- failure injection (loss/restart/path migration)

## Deliverables

1. `vm/quic-proxy-real/` daemon source + systemd unit
2. PKI helper scripts for test CA/server/client certs
3. `vm/quic-test-matrix.sh` and result artifacts
4. Hardening patchset in `src/transport/transport_quic.c`

## Immediate Next Step

Implement Phase 1 with `msquic`-based proxy daemon in `vm/quic-proxy-real/`, keep emulator as fallback for local kernel path diagnostics.
