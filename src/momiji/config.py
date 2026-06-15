import os
from typing import Literal
from dataclasses import dataclass, field
from .tls import TLSConfig

@dataclass
class Config:
    workers: int = 0

    keepalive_timeout: float = 75

    protocols: list[Literal["http/1.1", "h2", "h3"]] = field(default_factory=lambda: ["h3", "h2", "http/1.1"])

    bind_unix:  list[os.PathLike] = field(default_factory=list)
    bind_http:  list[str] = field(default_factory=lambda: ["127.0.0.1:80", "[::1]:80"])
    bind_https: list[str] = field(default_factory=list)
    bind_quic:  list[str] = field(default_factory=list)

    tls: TLSConfig = field(default_factory=lambda: TLSConfig())
