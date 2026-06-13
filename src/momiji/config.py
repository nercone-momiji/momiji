class Config:
    workers: int = 0

    # Protocols
    alpn_protocols = ["h3", "h2", "http/1.1"]

    # Ports
    bind_http:  list[str] = ["0.0.0.0:80",  "[::]:80"]
    bind_https: list[str] = []
    bind_quic:  list[str] = []

    # SSL/TLS
    certfile: str | None = None
    keyfile:  str | None = None
    ciphers: str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305"
    groups:  str = "X25519MLKEM768:SECP384R1MLKEM1024:SECP256R1MLKEM768:MLKEM1024:MLKEM768:X25519:prime256v1:secp384r1"
