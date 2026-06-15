from __future__ import annotations

import os
import gzip
import zlib
import inspect
import zstandard
import brotlicffi

import minify_html as rhtmin
import rjsmin
import rcssmin
from scour import scour

from typing import TYPE_CHECKING
from async_lru import alru_cache

from .models import Request, Response

if TYPE_CHECKING:
    from ..app import App

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
        try:
            if content_type.startswith("text/html"):
                return await minimize_html(response.body)
            elif content_type.startswith("text/css"):
                return await minimize_css(response.body)
            elif content_type.startswith(("text/javascript", "application/javascript")):
                return await minimize_js(response.body)
            elif content_type.startswith("image/svg"):
                return await minimize_svg(response.body)
        except Exception:
            return None
    return None

async def compress(response: Response, accepted_encodings: dict[str, float]) -> bytes | None:
    if not (response.has_real_body and response.compression and len(accepted_encodings) > 0):
        return None

    candidates: list[tuple[str, callable, int]] = [
        ("zstd", compress_zstd, 0),
        ("br", compress_brotli, 1),
        ("gzip", compress_gzip, 2),
        ("deflate", compress_deflate, 3)
    ]

    star_q = accepted_encodings.get("*", None)

    scored: list[tuple[float, int, str, callable]] = []
    for encoding, fn, priority in candidates:
        q = accepted_encodings.get(encoding)
        if q is None:
            q = star_q
        if q is None or q <= 0:
            continue
        scored.append((-q, priority, encoding, fn))

    scored.sort()

    for _, _, encoding, fn in scored:
        try:
            compressed = await fn(response.body)
        except Exception:
            continue

        response.headers.set("Content-Encoding", encoding)
        existing_vary = response.headers.get("Vary", "")
        vary_tokens = [v.strip() for v in existing_vary.split(",") if v.strip()]
        if not any(v.lower() == "accept-encoding" for v in vary_tokens):
            vary_tokens.append("Accept-Encoding")
        response.headers.set("Vary", ", ".join(vary_tokens))
        return compressed

    return None

def parse_accept_encoding(value: str) -> dict[str, float]:
    result: dict[str, float] = {}
    if not value:
        return result

    for item in value.split(","):
        token, _, params = item.strip().partition(";")
        token = token.strip().lower()
        if not token:
            continue

        q = 1.0
        for param in params.split(";"):
            param = param.strip()
            if param.startswith("q="):
                try:
                    q = float(param[2:])
                except ValueError:
                    q = 0.0
                break

        result[token] = q

    return result

async def process(app: App | None, request: Request, response: Response | None = None) -> Response:
    if response is None:
        try:
            result = app(request)
            if inspect.isawaitable(result):
                result = await result
            response = result
            response.protocol = response.protocol or request.protocol
        except Exception:
            response = Response(b"Internal Server Error", status_code=500, compression=False, minification=False, protocol=request.protocol)

    response.headers.set("Server", "Momiji", override=False)
    
    response.headers.set("Content-Type", "application/octet-stream", override=False)
    response.headers.set("Content-Length", "0")

    if response.has_real_body:
        response.body = await minimize(response) or response.body
        response.body = await compress(response, parse_accept_encoding(request.headers.get("accept-encoding", ""))) or response.body

        response.headers.set("Content-Length", str(len(response.body)))

    elif response.body is not None:
        try:
            response.headers.set("Content-Length", str(os.path.getsize(os.fspath(response.body))))
        except OSError:
            pass

    return response
