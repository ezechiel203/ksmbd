#!/usr/bin/env python3

import socket
import struct


def main() -> None:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("\x00ksmbd-quic")

    # struct ksmbd_quic_conn_info (packed)
    hdr = struct.pack(
        "<HHHH16s",
        socket.AF_INET,
        44500,
        1,
        0,
        b"\x7f\x00\x00\x01" + (b"\x00" * 12),
    )
    s.sendall(hdr)

    # Send one tiny fake RFC1002 frame
    s.sendall(b"\x00\x00\x00\x04TEST")
    s.close()


if __name__ == "__main__":
    main()
