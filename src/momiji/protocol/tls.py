import ssl
import ctypes
import ctypes.util
from enum import Enum
from typing import TYPE_CHECKING, Literal
from dataclasses import dataclass

if TYPE_CHECKING:
    from ..config import Config

class Group(Enum):
    # Classic
    X25519     = "x25519"
    prime256v1 = "prime256v1"
    secp384r1  = "secp384r1"
    secp521r1  = "secp521r1"

    # Pure PQC
    MLKEM512   = "MLKEM512"
    MLKEM768   = "MLKEM768"
    MLKEM1024  = "MLKEM1024"

    # Hybrid PQC
    X25519MLKEM768     = "X25519MLKEM768"
    SECP256R1MLKEM768  = "SecP256r1MLKEM768"
    SECP384R1MLKEM1024 = "SecP384r1MLKEM1024"

class Cipher(Enum):
    # TLS 1.2
    ECDHE_ECDSA_AES128_GCM_SHA256 = "ECDHE-ECDSA-AES128-GCM-SHA256"
    ECDHE_ECDSA_AES256_GCM_SHA384 = "ECDHE-ECDSA-AES256-GCM-SHA384"
    ECDHE_ECDSA_CHACHA20_POLY1305 = "ECDHE-ECDSA-CHACHA20-POLY1305"
    ECDHE_RSA_AES128_GCM_SHA256   = "ECDHE-RSA-AES128-GCM-SHA256"
    ECDHE_RSA_AES256_GCM_SHA384   = "ECDHE-RSA-AES256-GCM-SHA384"
    ECDHE_RSA_CHACHA20_POLY1305   = "ECDHE-RSA-CHACHA20-POLY1305"

    # TLS 1.3
    TLS_AES_128_GCM_SHA256       = "TLS_AES_128_GCM_SHA256"
    TLS_AES_256_GCM_SHA384       = "TLS_AES_256_GCM_SHA384"
    TLS_CHACHA20_POLY1305_SHA256 = "TLS_CHACHA20_POLY1305_SHA256"

@dataclass
class TLSInfo:
    version: Literal["1.0", "1.1", "1.2", "1.3"] | None
    group: Group | None
    cipher: Cipher | None

VERSION_MAP: dict[str, Literal["1.0", "1.1", "1.2", "1.3"]] = {
    "TLSv1":   "1.0",
    "TLSv1.1": "1.1",
    "TLSv1.2": "1.2",
    "TLSv1.3": "1.3"
}

GROUP_MAP: dict[str, Group] = {
    "x25519":             Group.X25519,
    "X25519":             Group.X25519,
    "prime256v1":         Group.prime256v1,
    "P-256":              Group.prime256v1,
    "secp384r1":          Group.secp384r1,
    "P-384":              Group.secp384r1,
    "secp521r1":          Group.secp521r1,
    "P-521":              Group.secp521r1,
    "MLKEM512":           Group.MLKEM512,
    "MLKEM768":           Group.MLKEM768,
    "MLKEM1024":          Group.MLKEM1024,
    "X25519MLKEM768":     Group.X25519MLKEM768,
    "SecP256r1MLKEM768":  Group.SECP256R1MLKEM768,
    "SecP384r1MLKEM1024": Group.SECP384R1MLKEM1024
}

CIPHER_MAP: dict[str, Cipher] = {c.value: c for c in Cipher}

def extract_tls_info(ssl_object: ssl.SSLObject | None) -> TLSInfo:
    if ssl_object is None:
        return None
    version = VERSION_MAP.get(ssl_object.version() or '')
    cipher_tuple = ssl_object.cipher()
    cipher_name = cipher_tuple[0] if cipher_tuple else ''
    cipher = CIPHER_MAP.get(cipher_name)
    if hasattr(ssl_object, 'group'):
        group = GROUP_MAP.get(ssl_object.group())
    else:
        group = None
    return TLSInfo(version=version, cipher=cipher, group=group)

def set_ssl_groups(ctx: ssl.SSLContext, groups: str) -> None:
    if hasattr(ctx, 'set_groups'):
        ctx.set_groups(groups)
        return
    libssl_name = ctypes.util.find_library('ssl')
    if not libssl_name:
        return
    try:
        libssl = ctypes.CDLL(libssl_name)
        libssl.SSL_CTX_set1_groups_list.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        libssl.SSL_CTX_set1_groups_list.restype = ctypes.c_int
        ptr_size = ctypes.sizeof(ctypes.c_void_p)
        ssl_ctx_ptr = ctypes.c_void_p.from_address(id(ctx) + 2 * ptr_size).value
        if ssl_ctx_ptr:
            libssl.SSL_CTX_set1_groups_list(ssl_ctx_ptr, groups.encode('ascii'))
    except Exception:
        pass

def create_ssl_context(config: 'Config') -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(config.certfile, config.keyfile)
    ctx.set_ciphers(':'.join(c.value for c in config.ciphers))
    https_alpn = [p for p in config.alpn_protocols if p != 'h3']
    if https_alpn:
        ctx.set_alpn_protocols(https_alpn)
    groups_str = ':'.join(g.value for g in config.groups)
    set_ssl_groups(ctx, groups_str)
    return ctx
