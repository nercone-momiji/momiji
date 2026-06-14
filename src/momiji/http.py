from __future__ import annotations

import ssl
import asyncio
import ipaddress
import puremagic
from async_lru import alru_cache
from typing import TYPE_CHECKING, Literal
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
from .tls import Group, Cipher, VERSION_MAP, CIPHER_MAP, GROUP_MAP

if TYPE_CHECKING:
    from .app import App

@dataclass
class TLSInfo:
    version: Literal["1.0", "1.1", "1.2", "1.3"] | None
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

    protocol: Literal["HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]
    method: Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
    target: str
    headers: Headers
    body: bytes | None

    tls: TLSInfo | None
    quic: QUICInfo | None

@dataclass
class Response:
    body: bytes | None = None
    status_code: int = 200
    headers: Headers = field(default_factory=lambda: Headers({}))

    compression: bool = True
    minification: bool = False

class Headers:
    def __init__(self, headers: dict[str, str]):
        self.headers: dict[str, list[str]] = {}
        for k, v in headers.items():
            self.append(k, v)

    def __getitem__(self, key: str) -> str | None:
        return self.get(key)

    def __setitem__(self, key: str, value: str):
        self.set(key, value)

    def __contains__(self, item: str):
        return item.lower() in self.headers

    def get(self, key: str, default=None) -> str | None:
        if key in self.headers:
            return ", ".join(self.headers.get(key.lower()))
        else:
            return default

    def get_all(self, key: str) -> list[str] | None:
        return self.headers.get(key.lower())

    def set(self, key: str, value: str, override: bool = True):
        if override or key.lower() not in self.headers:
            self.headers[key.lower()] = [value]

    def append(self, key: str, value: str):
        key = key.lower()
        if key in self.headers:
            self.headers[key].append(value)
        else:
            self.headers[key] = [value]

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

async def minimize(type: str, body: bytes) -> bytes | None:
    if type.startswith("text/html"):
        return await minimize_html(body)
    elif type.startswith("text/css"):
        return await minimize_css(body)
    elif type.startswith(("text/javascript", "application/javascript")):
        return await minimize_js(body)
    elif type.startswith("image/svg"):
        return await minimize_svg(body)
    else:
        return None

async def compress(type: str, body: bytes) -> bytes | None:
    if type == "zstd":
        return await compress_zstd(body)
    elif type == "br":
        return await compress_brotli(body)
    elif type == "gzip":
        return await compress_gzip(body)
    elif type == "deflate":
        return await compress_deflate(body)
    else:
        return None

def sniff_content_type(body: bytes) -> str:
    try:
        mime = puremagic.from_string(body, mime=True)
    except puremagic.PureError:
        try:
            body.decode("utf-8")
            mime = "text/plain"
        except UnicodeDecodeError:
            mime = "application/octet-stream"
    if mime.startswith("text/") and "charset" not in mime:
        mime += "; charset=utf-8"
    return mime

async def process(app: App, request: Request) -> Response:
    try:
        response = app(request)
    except Exception:
        response = Response(b"Internal Server Error", status_code=500)

    response.headers.set("Server", "Momiji", override=False)

    if response.body:
        response.headers.set("content-type", sniff_content_type(response.body), override=False)

        minimized = False
        if response.minification:
            content_type = response.headers.get("content-type", "")
            if minimized_body := await minimize(content_type, response.body):
                minimized = True
                response.body = minimized_body

        compressed = False
        if response.compression:
            for encoding in ["zstd", "br", "gzip", "deflate"]:
                if not encoding in request.headers.get("accept-encoding", "").split(", "):
                    continue
                compressed = True
                response.body = await compress(encoding, response.body)
                response.headers.set("Content-Encoding", encoding)

    response.headers.set("Content-Length", str(len(response.body) if response.body else 0), override=minimized or compressed)

    return response

async def parse(request: bytes) -> Request:
    ...

async def build(response: Response) -> bytes:
    ...

async def handle(app: App, config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    ...
