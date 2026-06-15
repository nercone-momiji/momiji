from __future__ import annotations

import ipaddress
from typing import Literal

from .models import Request, Headers, TLSInfo, QUICInfo

METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}

TOKEN_CHARS = frozenset(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
FIELD_VCHAR = frozenset(range(0x20, 0x7F)) | {0x09} | set(range(0x80, 0x100))

FORBIDDEN_H2_HEADERS = {"connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade"}
PSEUDO_HEADERS_REQUEST = {":method", ":scheme", ":authority", ":path", ":protocol"}

class ParseError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code

def parse_client(client: tuple) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    host, port = client[0], client[1]
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]), port
    except (ValueError, AttributeError):
        return host, port

def validate_token(name: bytes) -> None:
    if not name:
        raise ParseError("empty header name")

    for byte in name:
        if byte not in TOKEN_CHARS:
            raise ParseError("invalid character in header name")

def validate_field_value(value: bytes) -> None:
    for byte in value:
        if byte not in FIELD_VCHAR:
            raise ParseError("invalid character in header value")

async def parse(data: bytes, *, protocol: Literal["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"] = "HTTP/1.1", client: tuple, scheme: Literal["http", "https"] = "http", secure: bool = False, tls: TLSInfo | None = None, quic: QUICInfo | None = None, fields: list[tuple[bytes, bytes]] | None = None) -> Request:
    if fields is None:
        return parse_h1(data, protocol=protocol, client=client, scheme=scheme, secure=secure, tls=tls, quic=quic)
    return parse_fields(data, fields, protocol=protocol, client=client, scheme=scheme, secure=secure, tls=tls, quic=quic)

def validate_target(target: str) -> None:
    if not target:
        raise ParseError("empty request target")
    for ch in target:
        code = ord(ch)
        if code < 0x21 or code == 0x7F:
            raise ParseError("invalid character in request target")

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
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        raise ParseError("unsupported http version", 505)
    validate_target(target)

    headers = Headers({})
    for line in lines[1:]:
        if not line:
            continue
        if line[0:1] in (b" ", b"\t"):
            raise ParseError("obsolete line folding not allowed")
        name, sep, value = line.partition(b":")
        if not sep:
            raise ParseError("malformed header line")
        validate_token(name)
        value_bytes = value.strip(b" \t")
        validate_field_value(value_bytes)
        headers.append(name.decode("latin-1"), value_bytes.decode("latin-1"))

    has_body_indicator = "content-length" in headers or "transfer-encoding" in headers
    request_body: bytes | None = body if (body or has_body_indicator) else None

    return Request(client=parse_client(client), scheme=scheme, secure=secure, protocol="HTTP/1.1", method=method, target=target, headers=headers, body=request_body, tls=tls, quic=quic)

def parse_fields(body, fields, *, protocol, client, scheme, secure, tls, quic) -> Request:
    method = target = authority = pseudo_scheme = None
    pseudo_seen: set[str] = set()
    headers = Headers({})
    seen_regular = False

    for name, value in fields:
        if not name:
            raise ParseError("empty header name")

        if any(b < 0x20 or b == 0x7F for b in value):
            raise ParseError("invalid character in header value")

        name_s = name.decode("latin-1")
        value_s = value.decode("latin-1")

        if any(c.isupper() for c in name_s):
            raise ParseError("uppercase header name not allowed in h2/h3")

        if name_s.startswith(":"):
            if seen_regular:
                raise ParseError("pseudo-header after regular header")
            if name_s in pseudo_seen:
                raise ParseError(f"duplicate pseudo-header {name_s}")
            pseudo_seen.add(name_s)
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
            validate_token(name)
            if name_s in FORBIDDEN_H2_HEADERS:
                raise ParseError(f"forbidden header in h2/h3: {name_s}")
            if name_s == "te" and value_s.strip().lower() != "trailers":
                raise ParseError("te header must be 'trailers' in h2/h3")
            headers.append(name_s, value_s)

    if method is None:
        raise ParseError("missing :method")

    if method not in METHODS:
        raise ParseError("unsupported method", 501)

    if method == "CONNECT":
        if pseudo_scheme is not None or target is not None:
            raise ParseError(":scheme/:path forbidden for CONNECT")
        if authority is None:
            raise ParseError("CONNECT requires :authority")
        target = authority
    else:
        if target is None:
            raise ParseError("missing :path")
        if pseudo_scheme is None:
            raise ParseError("missing :scheme")
        if target == "":
            raise ParseError("empty :path")
        validate_target(target)

    if authority is not None:
        existing_host = headers.get("host")
        if existing_host is not None and existing_host != authority:
            raise ParseError(":authority and host header disagree")
        headers.set("host", authority, override=True)

    transport_scheme: Literal["http", "https"] = "https" if scheme == "https" else "http"

    has_body_indicator = "content-length" in headers or method in ("POST", "PUT", "PATCH")
    request_body: bytes | None = body if (body or has_body_indicator) else None

    return Request(client=parse_client(client), scheme=transport_scheme, secure=secure, protocol=protocol, method=method, target=target, headers=headers, body=request_body, tls=tls, quic=quic)
