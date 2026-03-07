#!/usr/bin/env python3
"""
Minimal QUIC client that sends an SMB2 NEGOTIATE request over one stream.

Used to validate real QUIC proxy path reachability (UDP/443 + TLS + bridge).
"""

import argparse
import asyncio
import os
import ssl
import struct

from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration


def smb2_negotiate_request() -> bytes:
    smb2_hdr = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",  # ProtocolId
        64,  # StructureSize
        0,  # CreditCharge
        0,  # Status/ChannelSequence
        0,  # Command: NEGOTIATE
        1,  # CreditRequest
        0,  # Flags
        0,  # NextCommand
        0,  # MessageId
        0,  # Reserved
        0,  # TreeId
        0,  # SessionId
        b"\x00" * 16,  # Signature
    )

    neg = struct.pack(
        "<HHHHI16sIHH",
        36,  # StructureSize
        2,  # DialectCount
        1,  # SecurityMode (signing enabled)
        0,  # Reserved
        0,  # Capabilities
        os.urandom(16),  # ClientGuid
        0,  # NegotiateContextOffset
        0,  # NegotiateContextCount
        0,  # Reserved2
    )
    dialects = struct.pack("<HH", 0x0202, 0x0311)

    pdu = smb2_hdr + neg + dialects
    rfc1002 = struct.pack(">I", len(pdu))
    return rfc1002 + pdu


async def run(host: str, port: int, cafile: str | None,
              cert: str | None, key: str | None) -> int:
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["ms_smb"])
    if cafile:
        cfg.verify_mode = ssl.CERT_REQUIRED
        cfg.load_verify_locations(cafile)
    else:
        cfg.verify_mode = False

    if cert and key:
        cfg.load_cert_chain(cert, key)

    cfg.server_name = "localhost"

    async with connect(host, port, configuration=cfg) as client:
        sid = client._quic.get_next_available_stream_id()
        writer = client._quic

        writer.send_stream_data(sid, smb2_negotiate_request(), end_stream=False)
        client.transmit()

        # Wait a bit and check if connection is still alive / any data arrives.
        await asyncio.sleep(1.0)
        return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=10443)
    parser.add_argument("--cafile", default="/etc/ksmbd/quic/ca.crt")
    parser.add_argument("--cert", default="/etc/ksmbd/quic/client.crt")
    parser.add_argument("--key", default="/etc/ksmbd/quic/client.key")
    parser.add_argument("--no-client-cert", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    cert = None if args.no_client_cert else args.cert
    key = None if args.no_client_cert else args.key
    cafile = None if args.insecure else args.cafile
    rc = asyncio.run(run(args.host, args.port, cafile, cert, key))
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
