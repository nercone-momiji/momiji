from __future__ import annotations

import os
import socket
import ipaddress
from typing import TYPE_CHECKING, Literal
from dataclasses import dataclass, field

from ..tls import TLSInfo

if TYPE_CHECKING:
    from .h2 import H2Info
    from .h3 import H3Info

@dataclass
class Listener:
    sock: socket.socket
    kind: Literal["http", "https", "quic", "unix"]

@dataclass
class Request:
    client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]
    scheme: Literal["http", "https"]
    secure: bool

    protocol: Literal["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]
    method: Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
    target: str
    headers: Headers
    body: bytes | None

    h2: H2Info | None
    h3: H3Info | None
    tls: TLSInfo | None

@dataclass
class Response:
    body: bytes | os.PathLike | None = None
    status_code: int = 200
    headers: Headers = field(default_factory=lambda: Headers({}))
    content_type: str | None = None
    protocol: Literal["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"] | None = None

    compression: bool = True
    minification: bool = False

    @property
    def has_real_body(self) -> bool:
        return self.body is not None and isinstance(self.body, bytes)

class Headers:
    def __init__(self, headers: dict[str, str]):
        self.headers: dict[str, list[str]] = {}
        for k, v in headers.items():
            self.append(k, v)

    def __getitem__(self, key: str) -> str | None:
        return self.get(key.lower())

    def __setitem__(self, key: str, value: str):
        self.set(key.lower(), value)

    def __contains__(self, item: str):
        return item.lower() in self.headers

    def items(self) -> list[tuple[str, str]]:
        return [(k, v) for k, values in self.headers.items() for v in values]

    def get(self, key: str, default=None) -> str | list[str] | None:
        values = self.headers.get(key.lower())
        if not values:
            return default
        if key.lower() == "set-cookie":
            return values
        return ", ".join(values)

    def set(self, key: str, value: str, override: bool = True):
        if override or key.lower() not in self.headers:
            self.headers[key.lower()] = [value]

    def append(self, key: str, value: str):
        if key.lower() in self.headers:
            self.headers[key.lower()].append(value)
        else:
            self.headers[key.lower()] = [value]

    def append_vary(self, header: str):
        vary = [v.strip() for v in self.get("Vary", "").split(",") if v.strip()]

        if not any(v.lower() == header.lower() for v in vary):
            vary.append(header)

        self.set("Vary", ", ".join(vary))
