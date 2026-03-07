#!/usr/bin/env python3
"""
Real QUIC-to-ksmbd proxy (development profile).

This daemon terminates QUIC/TLS using aioquic on UDP/443 and bridges the
first bidirectional QUIC stream to ksmbd's unix abstract socket @ksmbd-quic.

It sends ksmbd_quic_conn_info before forwarding payload data.
"""

import argparse
import asyncio
import socket
import ssl
import struct
from dataclasses import dataclass

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived


@dataclass
class BridgeState:
    sock: socket.socket | None = None
    stream_id: int | None = None
    closed: bool = False


def build_conn_info(peername: tuple[str, int], tls_verified: bool) -> bytes:
    ip, port = peername[0], int(peername[1])
    try:
        v4 = socket.inet_pton(socket.AF_INET, ip)
        family = socket.AF_INET
        addr = v4 + (b"\x00" * 12)
    except OSError:
        v6 = socket.inet_pton(socket.AF_INET6, ip)
        family = socket.AF_INET6
        addr = v6

    flags = 0x1 if tls_verified else 0x0
    return struct.pack("<HHHH16s", family, port, flags, 0, addr)


class KsmbdQuicProtocol(QuicConnectionProtocol):
    def __init__(self, *args, uds_name: str, tls_verified: bool, **kwargs):
        super().__init__(*args, **kwargs)
        self.uds_name = uds_name
        self.tls_verified = tls_verified
        self.require_client_cert = False
        self.bridge = BridgeState()

    def _client_cert_present(self) -> bool:
        tls = getattr(self._quic, "tls", None)
        if tls is None:
            return False

        peer_cert = getattr(tls, "_peer_certificate", None)
        if peer_cert:
            return True

        cert_chain = getattr(tls, "_peer_certificate_chain", None)
        return bool(cert_chain)

    async def _bridge_reader(self, sock: socket.socket) -> None:
        assert self.bridge.stream_id is not None
        sid = self.bridge.stream_id
        loop = asyncio.get_running_loop()
        try:
            while not self.bridge.closed:
                data = await loop.sock_recv(sock, 65536)
                if not data:
                    break
                self._quic.send_stream_data(sid, data, end_stream=False)
                self.transmit()
        finally:
            if not self.bridge.closed:
                self._quic.send_stream_data(sid, b"", end_stream=True)
                self.transmit()
                self.bridge.closed = True

    async def _ensure_bridge(self, sid: int) -> None:
        if self.bridge.sock is not None:
            return

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect("\x00" + self.uds_name)

        peer = ("127.0.0.1", 0)
        sock.sendall(build_conn_info(peer, self.tls_verified))
        print("bridge-connected sid=%d" % sid, flush=True)
        sock.setblocking(False)

        self.bridge.sock = sock
        self.bridge.stream_id = sid
        asyncio.create_task(self._bridge_reader(sock))

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            sid = event.stream_id
            cert_present = self._client_cert_present()
            print("cert-present=%s" % cert_present, flush=True)
            if self.require_client_cert and not self._client_cert_present():
                self._quic.close(
                    error_code=0x100,
                    reason_phrase="client certificate required",
                )
                self.transmit()
                self.bridge.closed = True
                return

            print("stream-data sid=%d bytes=%d end=%s" % (sid, len(event.data), event.end_stream), flush=True)

            async def handle_stream() -> None:
                try:
                    await self._ensure_bridge(sid)
                    if self.bridge.sock is not None:
                        loop = asyncio.get_running_loop()
                        await loop.sock_sendall(self.bridge.sock, event.data)
                        if event.end_stream and not self.bridge.closed:
                            try:
                                self.bridge.sock.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                except Exception:
                    print("bridge-failure sid=%d" % sid, flush=True)
                    if not self.bridge.closed:
                        self._quic.send_stream_data(sid, b"", end_stream=True)
                        self.transmit()
                        self.bridge.closed = True

            asyncio.create_task(handle_stream())


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="::")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--uds", default="ksmbd-quic")
    parser.add_argument("--cert", default="/etc/ksmbd/quic/server.crt")
    parser.add_argument("--key", default="/etc/ksmbd/quic/server.key")
    parser.add_argument("--cafile", default="/etc/ksmbd/quic/ca.crt")
    parser.add_argument("--alpn", default="ms_smb")
    parser.add_argument("--tls-verified", action="store_true")
    parser.add_argument("--require-client-cert", action="store_true")
    args = parser.parse_args()

    config = QuicConfiguration(is_client=False, alpn_protocols=[args.alpn])
    config.load_cert_chain(args.cert, args.key)
    if args.require_client_cert:
        config.verify_mode = ssl.CERT_REQUIRED
        config.load_verify_locations(args.cafile)

    def create_protocol(*p, **kw):
        proto = KsmbdQuicProtocol(
            *p,
            uds_name=args.uds,
            tls_verified=args.tls_verified,
            **kw,
        )
        proto.require_client_cert = args.require_client_cert
        return proto

    await serve(
        args.listen,
        args.port,
        configuration=config,
        create_protocol=create_protocol,
    )

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
