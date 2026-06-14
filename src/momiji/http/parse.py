from __future__ import annotations

import ipaddress
from typing import Literal

from .models import Request, Headers, TLSInfo, QUICInfo

METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}

class ParseError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code

def parse_client(client: tuple) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    host, port = client[0], client[1]
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]), port
    except ValueError:
        return host, port

async def parse(data: bytes, *, protocol: Literal["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"] = "HTTP/1.1", client: tuple, scheme: Literal["http", "https"] = "http", secure: bool = False, tls: TLSInfo | None = None, quic: QUICInfo | None = None, fields: list[tuple[bytes, bytes]] | None = None) -> Request:
    if fields is None:
        return parse_h1(data, protocol=protocol, client=client, scheme=scheme, secure=secure, tls=tls, quic=quic)
    return parse_fields(data, fields, protocol=protocol, client=client, scheme=scheme, secure=secure, tls=tls, quic=quic)

def parse_h1(data, *, protocol, client, scheme, secure, tls, quic) -> Request:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines or not lines[0]:
        raise ParseError("empty request line")

    try:
        method, target, version = lines[0].decode("latin-1").split(" ", 2)
    except ValueError:
        raise ParseError("malformed request line")
    if method not in METHODS:
        raise ParseError("unsupported method", 501)

    headers = Headers({})
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(b":")
        if not sep:
            raise ParseError("malformed header line")
        headers.append(name.decode("latin-1").strip(), value.decode("latin-1").strip())

    return Request(client=parse_client(client), scheme=scheme, secure=secure, protocol="HTTP/1.1", method=method, target=target, headers=headers, body=body or None, tls=tls, quic=quic)

def parse_fields(body, fields, *, protocol, client, scheme, secure, tls, quic) -> Request:
    method = target = authority = pseudo_scheme = None
    headers = Headers({})
    seen_regular = False
    for name, value in fields:
        name_s = name.decode("latin-1")
        value_s = value.decode("latin-1")
        if name_s.startswith(":"):
            if seen_regular:
                raise ParseError("pseudo-header after regular header")
            if name_s == ":method":
                method = value_s
            elif name_s == ":path":
                target = value_s
            elif name_s == ":scheme":
                pseudo_scheme = value_s
            elif name_s == ":authority":
                authority = value_s
            else:
                raise ParseError(f"unknown pseudo-header {name_s}")
        else:
            seen_regular = True
            headers.append(name_s, value_s)

    if method is None or target is None:
        raise ParseError("missing :method or :path")
    if method not in METHODS:
        raise ParseError("unsupported method", 501)
    if authority is not None and "host" not in headers:
        headers.set("host", authority)

    request_scheme: Literal["http", "https"] = "https" if (pseudo_scheme or scheme) == "https" else "http"

    return Request(client=parse_client(client), scheme=request_scheme, secure=secure, protocol=protocol, method=method, target=target, headers=headers, body=body or None, tls=tls, quic=quic)
