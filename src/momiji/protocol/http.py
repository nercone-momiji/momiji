import os
import ipaddress
from typing import Literal
from dataclasses import dataclass
from .tls import TLSInfo
from .quic import QUICInfo

@dataclass
class Request:
    client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]
    scheme: Literal["http", "https"]
    secure: bool

    protocol: Literal["HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]
    method: Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
    target: str
    headers: dict[str,str]
    body: bytes | None

    tls: TLSInfo | None
    quic: QUICInfo | None

@dataclass
class Response:
    status_code: int = 200
    headers: dict[str,str] = {}
    body: bytes | os.PathLike | None = None
