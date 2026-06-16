from __future__ import annotations

import os
import gzip
import zlib
import asyncio
import inspect
import mimetypes
import zstandard
import brotlicffi
import email.utils

import minify_html as rhtmin
import rjsmin
import rcssmin
from scour import scour

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from async_lru import alru_cache

from .models import Request, Response

if TYPE_CHECKING:
    from ..app import App, Middleware

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

async def compress_stream_zstd(body: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    compressor = zstandard.ZstdCompressor(level=3).compressobj()
    async for chunk in body:
        out = compressor.compress(chunk)
        if out:
            yield out
    out = compressor.flush(zstandard.COMPRESSOBJ_FLUSH_FINISH)
    if out:
        yield out

async def compress_stream_brotli(body: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    compressor = brotlicffi.Compressor(quality=4)
    async for chunk in body:
        out = compressor.process(chunk)
        if out:
            yield out
    out = compressor.finish()
    if out:
        yield out

async def compress_stream_gzip(body: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    compressor = zlib.compressobj(level=6, wbits=31)
    async for chunk in body:
        out = compressor.compress(chunk)
        if out:
            yield out
    out = compressor.flush(zlib.Z_FINISH)
    if out:
        yield out

async def compress_stream_deflate(body: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    compressor = zlib.compressobj(level=6)
    async for chunk in body:
        out = compressor.compress(chunk)
        if out:
            yield out
    out = compressor.flush(zlib.Z_FINISH)
    if out:
        yield out

async def minimize(response: Response) -> bytes | None:
    if response.has_real_body and response.minification:
        content_type = response.content_type or response.headers.get("Content-Type", "") or ""
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

def is_compressible(content_type: str | None) -> bool:
    if not content_type:
        return True

    ct = content_type.split(";", 1)[0].strip().lower()

    if ct.startswith(("image/", "video/", "audio/")):
        return ct == "image/svg+xml"

    elif ct in ("application/zip", "application/gzip", "application/x-gzip", "application/zstd", "application/x-zstd", "application/x-bzip2", "application/x-xz", "application/x-7z-compressed", "application/x-rar-compressed", "application/pdf", "application/ogg", "font/woff", "font/woff2"):
        return False

    return True

async def compress(response: Response, accepted_encodings: dict[str, float]) -> bytes | AsyncIterator[bytes] | None:
    if not (response.body is not None and response.compression and accepted_encodings):
        return None

    if "Content-Encoding" in response.headers:
        return None

    if not is_compressible(response.content_type or response.headers.get("Content-Type")):
        return None

    candidates: list[tuple[str, object, object, int]] = [
        ("zstd",    compress_zstd,    compress_stream_zstd,    0),
        ("br",      compress_brotli,  compress_stream_brotli,  1),
        ("gzip",    compress_gzip,    compress_stream_gzip,    2),
        ("deflate", compress_deflate, compress_stream_deflate, 3),
    ]

    star_q = accepted_encodings.get("*", None)

    scored: list[tuple[float, int, str, object, object]] = []
    for encoding, fn, stream_fn, priority in candidates:
        q = accepted_encodings.get(encoding)
        if q is None:
            q = star_q
        if q is None or q <= 0:
            continue
        scored.append((-q, priority, encoding, fn, stream_fn))

    scored.sort()

    for _, _, encoding, fn, stream_fn in scored:
        if response.is_streaming:
            response.headers.set("Content-Encoding", encoding)
            response.headers.append_vary("Accept-Encoding")
            return stream_fn(response.body)

        if response.has_real_body:
            try:
                compressed = await fn(response.body)
            except Exception:
                continue
            response.headers.set("Content-Encoding", encoding)
            response.headers.append_vary("Accept-Encoding")
            return compressed

        loop = asyncio.get_running_loop()
        try:
            path_str = os.fspath(response.body)
            data = await loop.run_in_executor(None, lambda: open(path_str, "rb").read())
            compressed = await fn(data)
        except Exception:
            continue

        response.headers.set("Content-Encoding", encoding)
        response.headers.append_vary("Accept-Encoding")

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

def parse_range(value: str, total: int) -> tuple[int, int] | None:
    if not value.startswith("bytes="):
        return None
    spec = value[6:].split(",")[0].strip()

    if spec.startswith("-"):
        try:
            suffix = int(spec[1:])
        except ValueError:
            return None
        if suffix <= 0 or total == 0:
            return None
        return (max(0, total - suffix), total - 1)

    dash = spec.find("-")
    if dash == -1:
        return None

    start_s, end_s = spec[:dash].strip(), spec[dash + 1:].strip()
    try:
        start = int(start_s)
    except ValueError:
        return None

    try:
        end = int(end_s) if end_s else total - 1
    except ValueError:
        return None
    if start > end or start >= total:
        return None

    return (start, min(end, total - 1))

def error_response(request: Request) -> Response:
    response = Response(b"Internal Server Error" if request.method != "HEAD" else None, status_code=500, compression=False, minification=False)
    response.headers.set("Date", email.utils.formatdate(usegmt=True), override=False)
    response.headers.set("Server", "Momiji", override=False)
    response.headers.set("Content-Type", "text/plain; charset=utf-8")
    response.headers.set("Content-Length", str(len(response.body)))
    return response

async def process(app: App | None, request: Request, response: Response | None = None, middlewares: list[Middleware] | None = None) -> Response:
    if response is None:
        for middleware in (middlewares or []):
            try:
                result = middleware.on_request(request)
                if inspect.isawaitable(result):
                    result = await result
            except Exception:
                response = Response(b"Internal Server Error", status_code=500, compression=False, minification=False)
                break

            if isinstance(result, Response):
                response = result
                break
            elif isinstance(result, Request):
                request = result

        if response is None:
            try:
                result = app.on_request(request)
                if inspect.isawaitable(result):
                    result = await result
                response = result
            except Exception:
                response = Response(b"Internal Server Error", status_code=500, compression=False, minification=False)

    if not isinstance(response, Response):
        response = Response(b"Internal Server Error", status_code=500, compression=False, minification=False)

    response.headers.set("Date", email.utils.formatdate(usegmt=True), override=False)
    response.headers.set("Server", "Momiji", override=False)
    response.headers.set("Content-Length", "0")

    try:
        if response.has_real_body:
            minimized = await minimize(response)
            if minimized is not None:
                response.body = minimized

            range_header = request.headers.get("Range", "")
            if (range_header and request.method in ("GET", "HEAD") and response.status_code == 200):
                total = len(response.body)
                parsed = parse_range(range_header, total)

                response.headers.set("Accept-Ranges", "bytes")

                if parsed is None:
                    response.status_code = 416
                    response.headers.set("Content-Range", f"bytes */{total}")
                    response.body = b""
                    response.headers.set("Content-Length", "0")
                    return response

                start, end = parsed
                response.body = response.body[start:end + 1]
                response.status_code = 206
                response.headers.set("Content-Range", f"bytes {start}-{end}/{total}")

            if response.status_code != 206:
                compressed = await compress(response, parse_accept_encoding(request.headers.get("Accept-Encoding", "")))
                if compressed is not None:
                    response.body = compressed

            response.headers.set("Content-Type", response.content_type or response.headers.get("Content-Type") or "application/octet-stream")
            response.headers.set("Content-Length", str(len(response.body)))

        elif response.is_streaming:
            compressed = await compress(response, parse_accept_encoding(request.headers.get("Accept-Encoding", "")))
            if compressed is not None:
                response.body = compressed

            response.headers.set("Content-Type", response.content_type or response.headers.get("Content-Type") or "application/octet-stream")
            response.headers.remove("Content-Length")

            if request.protocol == "HTTP/1.1":
                response.headers.set("Transfer-Encoding", "chunked")

        elif response.body is not None:
            loop = asyncio.get_running_loop()
            path = os.fspath(response.body)

            try:
                mime, _ = mimetypes.guess_type(path)
            except OSError:
                mime = None

            total = await loop.run_in_executor(None, os.path.getsize, path)

            response.headers.set("Accept-Ranges", "bytes")
            response.headers.set("Content-Type", response.content_type or response.headers.get("Content-Type") or mime or "application/octet-stream")

            range_header = request.headers.get("Range", "")
            if (range_header and request.method in ("GET", "HEAD") and response.status_code == 200):
                parsed = parse_range(range_header, total)
                if parsed is None:
                    response.status_code = 416
                    response.headers.set("Content-Range", f"bytes */{total}")
                    response.body = None
                    response.headers.set("Content-Length", "0")
                    return response

                start, end = parsed
                response.file_range = (start, end)
                response.status_code = 206
                response.headers.set("Content-Range", f"bytes {start}-{end}/{total}")
                response.headers.set("Content-Length", str(end - start + 1))

            else:
                compressed = await compress(response, parse_accept_encoding(request.headers.get("Accept-Encoding", "")))
                if compressed is not None:
                    response.body = compressed
                    response.headers.remove("Accept-Ranges")
                    response.headers.set("Content-Length", str(len(compressed)))
                else:
                    response.headers.set("Content-Length", str(total))

        if response.headers.get("Content-Type", "").startswith("text/") and "charset=" not in response.headers.get("Content-Type", ""):
            response.headers.set("Content-Type", response.headers.get("Content-Type", "") + "; charset=utf-8")

    except Exception:
        return error_response(request)

    if request.method == "HEAD":
        if response.is_streaming:
            response.headers.remove("Transfer-Encoding")
        response.body = None

    return response
