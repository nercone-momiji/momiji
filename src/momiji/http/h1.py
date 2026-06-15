from __future__ import annotations

import os
import asyncio
from http import HTTPStatus
from typing import TYPE_CHECKING

from .models import Response, TLSInfo
from .parse import parse, ParseError
from .process import process

if TYPE_CHECKING:
    from ..app import App
    from ..config import Config

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FORBIDDEN_HEADER_CHARS = ("\r", "\n", "\x00")

def sanitize_header_value(value: str) -> str:
    for ch in FORBIDDEN_HEADER_CHARS:
        if ch in value:
            value = value.replace("\r", " ").replace("\n", " ").replace("\x00", " ")
            break
    return value

def sanitize_header_name(name: str) -> str:
    name = name.strip()
    if any(c in name for c in (":", " ", "\t", "\r", "\n", "\x00")):
        raise ValueError(f"invalid header name: {name!r}")
    return name

def serialize_response(response: Response) -> bytes | tuple[bytes, os.PathLike | None]:
    try:
        phrase = HTTPStatus(response.status_code).phrase
    except ValueError:
        phrase = ""

    status_line = f"HTTP/1.1 {response.status_code}"
    if phrase:
        status_line += f" {phrase}"
    built = status_line + "\r\n"

    for key, value in response.headers.items():
        safe_name = sanitize_header_name(key)
        safe_value = sanitize_header_value(value)
        built += f"{safe_name}: {safe_value}\r\n"
    built += "\r\n"

    if response.has_real_body:
        return built.encode("latin-1") + response.body
    else:
        return built.encode("latin-1"), response.body

def framing(head: bytes) -> tuple[str, int]:
    content_length = 0
    chunked = False

    for line in head.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if not sep:
            continue

        name = name.strip().lower()
        value = value.strip().lower()

        if name == b"content-length":
            try:
                cl = int(value)
                if cl < 0:
                    raise ParseError("negative content-length", 400)
                content_length = cl
            except ValueError:
                raise ParseError("invalid content-length", 400)

        elif name == b"transfer-encoding" and b"chunked" in value:
            chunked = True

    if chunked:
        return "chunked", 0

    return "length", content_length

async def read_chunked(reader: asyncio.StreamReader, limit: int) -> bytes:
    body = bytearray()

    while True:
        size_line = await reader.readuntil(b"\r\n")
        try:
            size = int(size_line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            raise ParseError("invalid chunk size", 400)

        if size < 0:
            raise ParseError("negative chunk size", 400)

        if size == 0:
            await reader.readuntil(b"\r\n")
            break

        if len(body) + size > limit:
            raise ParseError("request body too large", 413)

        chunk = await reader.readexactly(size)
        await reader.readexactly(2)  # CRLF

        body += chunk

    return bytes(body)

async def read_body(reader: asyncio.StreamReader, head: bytes, config: Config) -> bytes:
    mode, length = framing(head)

    if mode == "chunked":
        return await read_chunked(reader, config.request_max_body_size)

    if length:
        if length > config.request_max_body_size:
            raise ParseError("request body too large", 413)

        return await reader.readexactly(length)

    return b""

def parse_request_version(head: bytes) -> str:
    try:
        first_line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = first_line.split(" ")
        if len(parts) >= 3:
            return parts[-1]
    except Exception:
        pass
    return "HTTP/1.1"

async def write(writer: asyncio.StreamWriter, built: bytes | tuple[bytes, os.PathLike | None]):
    if isinstance(built, tuple):
        head, body = built
        writer.write(head)

        if body is not None:
            loop = asyncio.get_event_loop()
            fd = await loop.run_in_executor(None, lambda: open(body, "rb"))
            try:
                while True:
                    chunk = await loop.run_in_executor(None, fd.read, 65536)
                    if not chunk:
                        break
                    writer.write(chunk)
                    await writer.drain()
            finally:
                await loop.run_in_executor(None, fd.close)

    else:
        writer.write(built)

    await writer.drain()

async def serve_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, app: App, config: Config, *, scheme: str = "http", secure: bool = False, tls: TLSInfo | None = None) -> None:
    peer = writer.get_extra_info("peername") or ("", 0)

    try:
        while True:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), config.request_read_timeout)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
                break
            except asyncio.LimitOverrunError:
                try:
                    response = Response(b"Request Header Too Large", status_code=431, compression=False, protocol="HTTP/1.1")
                    response.headers.set("Server", "Momiji", override=False)
                    response.headers.set("Content-Length", str(len(response.body)))
                    response.headers.set("Connection", "close")
                    await write(writer, serialize_response(response))
                except (ConnectionError, OSError):
                    pass
                break

            if len(head) > config.request_max_header_size:
                try:
                    response = Response(b"Request Header Too Large", status_code=431, compression=False, protocol="HTTP/1.1")
                    response.headers.set("Server", "Momiji", override=False)
                    response.headers.set("Content-Length", str(len(response.body)))
                    response.headers.set("Connection", "close")
                    await write(writer, serialize_response(response))
                except (ConnectionError, OSError):
                    pass
                break

            if head.startswith(b"PRI * HTTP/2.0"):
                from . import h2
                remaining = len(H2_PREFACE) - len(head)
                if remaining > 0:
                    try:
                        await reader.readexactly(remaining)
                    except asyncio.IncompleteReadError:
                        break
                await h2.serve_connection(reader, writer, app, config, scheme=scheme, secure=secure, tls=tls, preface_consumed=True)
                return

            request_version = parse_request_version(head)

            try:
                body = await asyncio.wait_for(read_body(reader, head, config), config.request_body_timeout)
                request = await parse(head + body, protocol="HTTP/1.1", client=peer, scheme=scheme, secure=secure, tls=tls)

            except (ParseError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ValueError) as exc:
                status = getattr(exc, "status_code", 400)
                try:
                    phrase = HTTPStatus(status).phrase
                except ValueError:
                    phrase = "Bad Request"
                response = Response(phrase.encode(), status_code=status, compression=False, protocol="HTTP/1.1")
                response.headers.set("Server", "Momiji", override=False)
                response.headers.set("Content-Length", str(len(response.body)))
                response.headers.set("Connection", "close")
                try:
                    await write(writer, serialize_response(response))
                except (ConnectionError, OSError):
                    pass
                break

            connection_header = request.headers.get("connection", "").lower()
            if request_version == "HTTP/1.0":
                keep_alive = "keep-alive" in connection_header
            else:
                keep_alive = connection_header != "close"

            try:
                response = await process(app, request)
            except Exception:
                response = Response(b"Internal Server Error", status_code=500, compression=False, protocol="HTTP/1.1")
                response.headers.set("Server", "Momiji", override=False)
                response.headers.set("Content-Length", str(len(response.body)))

            response.protocol = "HTTP/1.1"
            response.headers.set("Connection", "keep-alive" if keep_alive else "close", override=False)

            try:
                await write(writer, serialize_response(response))
            except (ConnectionError, OSError):
                break

            if not keep_alive:
                break

    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
