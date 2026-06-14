from __future__ import annotations

import os
import ipaddress
from http import HTTPStatus
from typing import TYPE_CHECKING, Literal
from async_lru import alru_cache
from dataclasses import dataclass, field

import gzip
import zlib
import zstandard
import brotlicffi

import minify_html as rhtmin
import rjsmin
import rcssmin
from scour import scour

from .config import Config
from .tls import Group, Cipher

if TYPE_CHECKING:
    from .app import App

@dataclass
class TLSInfo:
    version: Literal["SSLv3.0", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"] | None
    group: Group | None
    cipher: Cipher | None

@dataclass
class QUICInfo:
    connection_id: bytes
    stream_id: int

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

    tls: TLSInfo | None
    quic: QUICInfo | None

@dataclass
class Response:
    body: bytes | os.PathLike | None = None
    status_code: int = 200
    headers: Headers = field(default_factory=lambda: Headers({}))
    protocol: Literal["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]

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

    def get(self, key: str, default=None) -> str | None:
        if key.lower() in self.headers:
            return ", ".join(self.headers.get(key.lower()))
        else:
            return default

    def set(self, key: str, value: str, override: bool = True):
        if override or key.lower() not in self.headers:
            self.headers[key.lower()] = [value]

    def append(self, key: str, value: str):
        if key.lower() in self.headers:
            self.headers[key.lower()].append(value)
        else:
            self.headers[key.lower()] = [value]

    def items(self) -> list[tuple[str, str]]:
        return [(k, v) for k, values in self.headers.items() for v in values]

@alru_cache(maxsize=128)
async def minimize_html(body: bytes) -> bytes:
    return rhtmin.minify(body.decode("utf-8", errors="replace"), minify_js=True, minify_css=True, keep_comments=True, keep_html_and_head_opening_tags=True).encode("utf-8")

@alru_cache(maxsize=128)
async def minimize_css(body: bytes) -> bytes:
    return rcssmin.cssmin(body.decode("utf-8", errors="replace")).encode("utf-8")

@alru_cache(maxsize=128)
async def minimize_js(body: bytes) -> bytes:
    return rjsmin.jsmin(body.decode("utf-8", errors="replace")).encode("utf-8")

@alru_cache(maxsize=64)
async def minimize_svg(body: bytes) -> bytes:
    scour_options = scour.generateDefaultOptions()
    scour_options.newlines = False
    scour_options.shorten_ids = True
    scour_options.strip_comments = True
    return scour.scourString(body.decode("utf-8", errors="replace"), scour_options).encode("utf-8")

@alru_cache(maxsize=128)
async def compress_zstd(body: bytes) -> bytes:
    return zstandard.ZstdCompressor(level=3).compress(body)

@alru_cache(maxsize=128)
async def compress_brotli(body: bytes) -> bytes:
    return brotlicffi.compress(body, quality=4)

@alru_cache(maxsize=128)
async def compress_gzip(body: bytes) -> bytes:
    return gzip.compress(body, compresslevel=6)

@alru_cache(maxsize=128)
async def compress_deflate(body: bytes) -> bytes:
    return zlib.compress(body, level=6)

async def minimize(response: Response) -> bytes | None:
    if response.has_real_body and response.minification:
        content_type = response.headers.get("Content-Type", "")
        if content_type.startswith("text/html"):
            return await minimize_html(response.body)
        elif content_type.startswith("text/css"):
            return await minimize_css(response.body)
        elif content_type.startswith(("text/javascript", "application/javascript")):
            return await minimize_js(response.body)
        elif content_type.startswith("image/svg"):
            return await minimize_svg(response.body)
        else:
            return None

async def compress(response: Response, accepted_encodings: str = "") -> bytes | None:
    if response.has_real_body and response.compression and accepted_encodings:
        for encoding in ["zstd", "br", "gzip", "deflate"]:
            if not encoding in accepted_encodings:
                continue

            response.headers.set("Content-Encoding", encoding)

            if encoding == "zstd":
                return await compress_zstd(response.body)
            elif encoding == "br":
                return await compress_brotli(response.body)
            elif encoding == "gzip":
                return await compress_gzip(response.body)
            elif encoding == "deflate":
                return await compress_deflate(response.body)
            else:
                return None

async def process(app: App, request: Request) -> Response:
    try:
        response = app(request)
        response.protocol = response.protocol or request.protocol
    except Exception:
        response = Response(b"Internal Server Error", status_code=500, compression=False, minification=False, protocol=request.protocol)

    response.headers.set("Server", "Momiji", override=False)

    if response.has_real_body:
        response.body = await minimize(response) or response.body
        response.body = await compress(response, request.headers.get("accept-encoding", "")) or response.body

        response.headers.set("Content-Type", "application/octet-stream", override=False)
        response.headers.set("Content-Length", str(len(response.body)))

    return response

async def parse(request: bytes) -> Request:
    ...

async def build(response: Response) -> bytes | tuple[bytes, os.PathLike]:
    if response.protocol == "HTTP/1.1":
        built = f"{response.protocol} {response.status_code} {HTTPStatus(response.status_code).phrase}\n"
        for key, value in response.headers.items():
            built += f"{key.strip()}: {value}\n"
        built += "\n"

        if response.has_real_body:
            return built.encode("latin-1") + response.body
        else:
            return built.encode("latin-1"), response.body

async def handle(app: App, config: Config) -> None:
    ...
