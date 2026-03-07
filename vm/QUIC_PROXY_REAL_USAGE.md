# Real QUIC Proxy (Development) Usage

This repo now provides two QUIC bridge modes:

1. **Emulator** (`vm/quic-proxy-emulator.py`): TCP bridge, no real QUIC/TLS
2. **Real QUIC** (`vm/quic-real-proxy.py`): QUIC over UDP/443 via `aioquic`

## Prerequisites

- VM instance running with QUIC host forwards enabled (done by `vm/run-vm-instance.sh`):
  - `VM0`: `10443` -> guest `443` (tcp+udp)
  - `VM1`: `11443` -> guest `443` (tcp+udp)
  - `VM2`: `12443` -> guest `443` (tcp+udp)
- ksmbd module loaded with `CONFIG_SMB_SERVER_QUIC=y`.

## Install and Start (VM0..VM2)

```bash
./vm/quic-real-proxy.sh install VM0
./vm/quic-real-proxy.sh install VM1
./vm/quic-real-proxy.sh install VM2

./vm/quic-real-proxy.sh start VM0
./vm/quic-real-proxy.sh start VM1
./vm/quic-real-proxy.sh start VM2
```

## Check Status

```bash
./vm/quic-real-proxy.sh status VM0
./vm/quic-real-proxy.sh logs VM0
```

## Minimal QUIC Probe (inside each VM)

```bash
./vm/vm-exec-instance.sh VM0 /usr/bin/python3 /mnt/ksmbd/vm/quic-smb2-negotiate-client.py --host 127.0.0.1 --port 443
```

Expected proxy log sample:

- `stream-data sid=0 bytes=108 end=False`
- `bridge-connected sid=0`

## Compatibility Matrix (host side)

```bash
./vm/quic-compat-matrix.sh
```

This validates:

- real QUIC probe path on VM0..VM2,
- kernel rejection of non-root unix bridge peers,
- kernel enforcement of `KSMBD_QUIC_F_TLS_VERIFIED`,
- baseline SMB3 encrypted sanity.

## Important Notes

- This is a **development proxy** to exercise real QUIC transport and kernel bridge path.
- It is not yet production-grade SMB-over-QUIC:
  - strict client-cert rejection behavior still needs deeper handshake-policy work,
  - simplified peer address mapping,
  - stream policy is first-stream bridge behavior.
- Kernel-side unix-socket peer hardening is enforced: non-root proxy peers are rejected.
- For full compliance/interop plan, see `vm/QUIC_FULL_COMPLIANCE_PLAN.md`.
