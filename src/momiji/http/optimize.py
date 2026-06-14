from __future__ import annotations

from async_lru import alru_cache

import gzip
import zlib
import zstandard
import brotlicffi

import minify_html as rhtmin
import rjsmin
import rcssmin
from scour import scour

from .models import Response

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
