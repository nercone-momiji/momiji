from dataclasses import dataclass, field

@dataclass
class Config:
    workers: int = 0

    # Protocols
    alpn_protocols: list[str] = field(default_factory=lambda: ["h3", "h2", "http/1.1"])

    # Ports
    bind_http:  list[str] = field(default_factory=lambda: ["127.0.0.1:80", "[::1]:80"])
    bind_https: list[str] = field(default_factory=list)
    bind_quic:  list[str] = field(default_factory=list)

    # SSL/TLS
    certfile: str | None = None
    keyfile:  str | None = None
    ciphers: str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305"
    groups:  str = "X25519MLKEM768:SECP384R1MLKEM1024:SECP256R1MLKEM768:MLKEM1024:MLKEM768:X25519:prime256v1:secp384r1"
