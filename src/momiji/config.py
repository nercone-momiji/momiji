import os
from dataclasses import dataclass, field
from .protocol.tls import Group, Cipher

@dataclass
class Config:
    workers: int = 0

    # Protocols
    alpn_protocols: list[str] = field(default_factory=lambda: ["h3", "h2", "http/1.1"])

    # Ports
    bind_unix:  list[os.PathLike] = field(default_factory=list)
    bind_http:  list[str] = field(default_factory=lambda: ["127.0.0.1:80", "[::1]:80"])
    bind_https: list[str] = field(default_factory=list)
    bind_quic:  list[str] = field(default_factory=list)

    # SSL/TLS
    certfile: str | None = None
    keyfile:  str | None = None
    ciphers: list[Cipher] = field(default_factory=lambda: [Cipher.ECDHE_ECDSA_AES128_GCM_SHA256, Cipher.ECDHE_ECDSA_AES256_GCM_SHA384, Cipher.ECDHE_ECDSA_CHACHA20_POLY1305])
    groups: list[Group] = field(default_factory=lambda: [Group.X25519MLKEM768, Group.SECP384R1MLKEM1024, Group.SECP256R1MLKEM768, Group.MLKEM1024, Group.MLKEM768, Group.X25519, Group.prime256v1, Group.secp384r1])
