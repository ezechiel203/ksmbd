#!/usr/bin/env python3
"""
quic-proxy-emulator.py

Development helper that emulates the userspace SMB-over-QUIC proxy bridge.
It accepts TCP streams on port 443 and forwards raw SMB PDU bytes to the
kernel QUIC unix abstract socket (@ksmbd-quic), prepending the required
ksmbd_quic_conn_info header.

This does NOT implement real QUIC/TLS. It is only for exercising the kernel
QUIC transport path and proxy handoff logic in test environments.
"""

import argparse
import socket
import struct
import threading


def build_conn_info(client_ip: str, client_port: int, tls_verified: bool) -> bytes:
    try:
        v4 = socket.inet_pton(socket.AF_INET, client_ip)
        family = socket.AF_INET
        addr = v4 + (b"\x00" * 12)
    except OSError:
        v6 = socket.inet_pton(socket.AF_INET6, client_ip)
        family = socket.AF_INET6
        addr = v6

    flags = 0x1 if tls_verified else 0x0
    # struct ksmbd_quic_conn_info (__packed):
    # u16 family, u16 port, u16 flags, u16 reserved, union addr[16]
    return struct.pack("<HHHH16s", family, client_port, flags, 0, addr)


def pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(64 * 1024)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_client(client: socket.socket, uds_name: str, tls_verified: bool) -> None:
    peer_ip, peer_port = client.getpeername()[0], client.getpeername()[1]

    kernel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # Abstract unix socket: leading NUL byte.
        kernel.connect("\x00" + uds_name)
        kernel.sendall(build_conn_info(peer_ip, peer_port, tls_verified))

        t1 = threading.Thread(target=pump, args=(client, kernel), daemon=True)
        t2 = threading.Thread(target=pump, args=(kernel, client), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    finally:
        try:
            kernel.close()
        except OSError:
            pass
        try:
            client.close()
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="::", help="TCP listen address")
    parser.add_argument("--port", type=int, default=443, help="TCP listen port")
    parser.add_argument("--uds", default="ksmbd-quic", help="abstract unix socket name")
    parser.add_argument("--tls-verified", action="store_true", help="set TLS_VERIFIED flag")
    args = parser.parse_args()

    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    srv.bind((args.listen, args.port))
    srv.listen(128)

    while True:
        client, _ = srv.accept()
        threading.Thread(
            target=handle_client,
            args=(client, args.uds, args.tls_verified),
            daemon=True,
        ).start()


if __name__ == "__main__":
    main()
