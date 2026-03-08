#!/usr/bin/env python3
import argparse
import os
import select
import socket
import struct
import subprocess
import sys
import time
import uuid


SMB2_PROTO = b"\xfeSMB"
SMB2_NEGOTIATE = 0x0000
SMB311 = 0x0311

CTX_PREAUTH = 0x0001
CTX_TRANSPORT = 0x0006

SMB2_SIGNING_ENABLED = 0x0001
SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY = 0x00000001
PREAUTH_HASH_SHA512 = 0x0001

STATUS_SKIP = 77


def round_up(value: int, align: int) -> int:
    return (value + align - 1) & ~(align - 1)


def build_negotiate_request() -> bytes:
    client_guid = uuid.uuid4().bytes_le
    salt = bytes(range(32))

    preauth_data = struct.pack("<HHH", 1, len(salt), PREAUTH_HASH_SHA512) + salt
    preauth_ctx = struct.pack("<HHI", CTX_PREAUTH, len(preauth_data), 0) + preauth_data

    transport_data = struct.pack("<I", SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY)
    transport_ctx = struct.pack("<HHI", CTX_TRANSPORT, len(transport_data), 0) + transport_data

    dialects = struct.pack("<H", SMB311)
    dialects_offset = 64 + 36
    ctx_offset = round_up(dialects_offset + len(dialects), 8)
    dialect_pad = b"\x00" * (ctx_offset - (dialects_offset + len(dialects)))
    contexts = preauth_ctx
    contexts += b"\x00" * (round_up(len(preauth_ctx), 8) - len(preauth_ctx))
    contexts += transport_ctx

    header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        SMB2_PROTO,
        64,
        0,
        0,
        SMB2_NEGOTIATE,
        1,
        0,
        0,
        0,
        0xFEFF,
        0,
        0,
        b"\x00" * 16,
    )
    request = struct.pack(
        "<HHHHI16sIHH",
        36,
        1,
        SMB2_SIGNING_ENABLED,
        0,
        0,
        client_guid,
        ctx_offset,
        2,
        0,
    )

    return header + request + dialects + dialect_pad + contexts


def parse_negotiate_response(payload: bytes) -> dict:
    if len(payload) < 128:
        raise ValueError(f"response too short: {len(payload)} bytes")
    if payload[:4] != SMB2_PROTO:
        raise ValueError(f"unexpected protocol id: {payload[:4]!r}")

    status = struct.unpack_from("<I", payload, 8)[0]
    command = struct.unpack_from("<H", payload, 12)[0]
    if command != SMB2_NEGOTIATE:
        raise ValueError(f"unexpected command {command:#x}")

    dialect = struct.unpack_from("<H", payload, 68)[0]
    ctx_count = struct.unpack_from("<H", payload, 70)[0]
    secbuf_offset = struct.unpack_from("<H", payload, 120)[0]
    secbuf_len = struct.unpack_from("<H", payload, 122)[0]
    ctx_offset = struct.unpack_from("<I", payload, 124)[0]

    result = {
        "status": status,
        "dialect": dialect,
        "security_buffer_offset": secbuf_offset,
        "security_buffer_length": secbuf_len,
        "negotiate_context_offset": ctx_offset,
        "negotiate_context_count": ctx_count,
        "context_types": [],
        "has_transport_context": False,
    }

    if ctx_count == 0:
        return result

    offset = ctx_offset
    for _ in range(ctx_count):
        if offset + 8 > len(payload):
            raise ValueError("context header beyond payload")
        ctx_type, data_len, _reserved = struct.unpack_from("<HHI", payload, offset)
        total = 8 + data_len
        if offset + total > len(payload):
            raise ValueError("context data beyond payload")
        result["context_types"].append(ctx_type)
        if ctx_type == CTX_TRANSPORT:
            result["has_transport_context"] = True
        offset += round_up(total, 8)

    return result


def recv_tcp_response(host: str, port: int, timeout: float, request: bytes) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(struct.pack(">I", len(request)) + request)
        header = recv_at_least(sock, 4)
        if len(header) < 4:
            raise ConnectionError(f"short NBSS header: {len(header)} bytes")
        length = struct.unpack(">I", header)[0] & 0x00FFFFFF
        payload = recv_at_least(sock, length)
        if len(payload) < length:
            raise ConnectionError(f"short SMB payload: {len(payload)} of {length} bytes")
        return payload[:length]


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise ConnectionError(f"unexpected EOF after {len(chunks)} of {length} bytes")
        chunks.extend(chunk)
    return bytes(chunks)


def recv_at_least(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        try:
            chunk = sock.recv(length - len(chunks))
        except ConnectionResetError:
            break
        if not chunk:
            break
        chunks.extend(chunk)
    return bytes(chunks)


def recv_quic_response(host: str, port: int, timeout: float, request: bytes) -> bytes:
    openssl = shutil_which("openssl")
    if not openssl:
        raise SkipError("openssl not available")

    cmd = [
        openssl,
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-quic",
        "-alpn",
        "smb",
        "-quiet",
        "-ign_eof",
        "-servername",
        host,
    ]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        assert proc.stdin is not None
        assert proc.stdout is not None
        proc.stdin.write(request)
        proc.stdin.flush()
        payload = read_until_complete(proc.stdout, timeout)
        if not payload:
            err = b""
            if proc.stderr is not None:
                err = proc.stderr.read()
            raise SkipError(f"no QUIC SMB response received ({err.decode(errors='replace').strip()})")
        return payload
    finally:
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            proc.kill()


def read_until_complete(stream, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    buf = bytearray()
    target_len = None
    fd = stream.fileno()

    while time.monotonic() < deadline:
        wait = max(0.0, min(0.2, deadline - time.monotonic()))
        readable, _, _ = select.select([fd], [], [], wait)
        if readable:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            buf.extend(chunk)
            target_len = expected_quic_response_len(bytes(buf))
            if target_len is not None and len(buf) >= target_len:
                return bytes(buf[:target_len])
        elif buf:
            target_len = expected_quic_response_len(bytes(buf))
            if target_len is not None and len(buf) >= target_len:
                return bytes(buf[:target_len])

    if target_len is not None and len(buf) >= target_len:
        return bytes(buf[:target_len])
    return bytes(buf)


def expected_quic_response_len(buf: bytes):
    if len(buf) < 128 or buf[:4] != SMB2_PROTO:
        return None

    ctx_count = struct.unpack_from("<H", buf, 70)[0]
    secbuf_offset = struct.unpack_from("<H", buf, 120)[0]
    secbuf_len = struct.unpack_from("<H", buf, 122)[0]
    ctx_offset = struct.unpack_from("<I", buf, 124)[0]
    min_len = max(128, secbuf_offset + secbuf_len)

    if ctx_count == 0:
        return min_len
    if len(buf) < ctx_offset + 8:
        return None

    offset = ctx_offset
    for _ in range(ctx_count):
        if len(buf) < offset + 8:
            return None
        _ctx_type, data_len, _reserved = struct.unpack_from("<HHI", buf, offset)
        total = 8 + data_len
        if len(buf) < offset + total:
            return None
        offset += round_up(total, 8)

    return max(min_len, offset)


def shutil_which(binary: str):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        path = os.path.join(directory, binary)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


class SkipError(RuntimeError):
    pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe SMB NEGOTIATE response contexts over TCP or QUIC")
    parser.add_argument("--transport", choices=["tcp", "quic"], required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--expect-transport-context", choices=["present", "absent"], required=True)
    args = parser.parse_args()

    request = build_negotiate_request()

    try:
        if args.transport == "tcp":
            payload = recv_tcp_response(args.host, args.port, args.timeout, request)
        else:
            payload = recv_quic_response(args.host, args.port, args.timeout, request)
        result = parse_negotiate_response(payload)
    except SkipError as exc:
        print(f"skip: {exc}", file=sys.stderr)
        return STATUS_SKIP
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    expect_present = args.expect_transport_context == "present"
    actual_present = result["has_transport_context"]
    print(
        f"transport={args.transport} dialect=0x{result['dialect']:04x} "
        f"contexts={result['context_types']} "
        f"transport_context={'present' if actual_present else 'absent'}"
    )

    if actual_present != expect_present:
        print(
            f"error: expected transport context {args.expect_transport_context}, "
            f"got {'present' if actual_present else 'absent'}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
