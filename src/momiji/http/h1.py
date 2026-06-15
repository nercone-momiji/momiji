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

def serialize_response(response: Response) -> bytes | tuple[bytes, os.PathLike | None]:
    try:
        phrase = HTTPStatus(response.status_code).phrase
    except ValueError:
        phrase = ""

    built = f"HTTP/1.1 {response.status_code} {phrase}\r\n"
    for key, value in response.headers.items():
        built += f"{key.strip()}: {value}\r\n"
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
                content_length = int(value)
            except ValueError:
                content_length = 0

        elif name == b"transfer-encoding" and b"chunked" in value:
            chunked = True

    if chunked:
        return "chunked", 0

    return "length", content_length

async def read_chunked(reader: asyncio.StreamReader, limit: int) -> bytes:
    body = bytearray()

    while True:
        size_line = await reader.readuntil(b"\r\n")
        size = int(size_line.split(b";", 1)[0].strip(), 16)

        if size == 0:
            await reader.readuntil(b"\r\n")
            break

        chunk = await reader.readexactly(size)
        await reader.readexactly(2)  # CRLF

        body += chunk

        if len(body) > limit:
            raise ParseError("request body too large", 413)

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

async def write(writer: asyncio.StreamWriter, built: bytes | tuple[bytes, os.PathLike | None]):
    if isinstance(built, tuple):
        head, body = built
        writer.write(head)

        if body is not None:
            with open(body, "rb") as f:
                while chunk := f.read(65536):
                    writer.write(chunk)
                    await writer.drain()

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

            if head.startswith(b"PRI * HTTP/2.0"):
                from . import h2
                rest = await reader.readexactly(len(H2_PREFACE) - len(head))
                await h2.serve_connection(reader, writer, app, config, scheme=scheme, secure=secure, tls=tls, preface_consumed=True)
                return

            try:
                body = await read_body(reader, head, config)
                request = await parse(head + body, protocol="HTTP/1.1", client=peer, scheme=scheme, secure=secure, tls=tls)

            except (ParseError, asyncio.IncompleteReadError, ValueError) as exc:
                status = getattr(exc, "status_code", 400)
                response = Response(HTTPStatus(status).phrase.encode(), status_code=status, compression=False, protocol="HTTP/1.1")
                response.headers.set("Server", "Momiji", override=False)
                response.headers.set("Content-Length", str(len(response.body)))
                response.headers.set("Connection", "close")
                await write(writer, serialize_response(response))
                break

            keep_alive = (request.headers.get("connection", "").lower() != "close")

            response = await process(app, request)
            response.protocol = "HTTP/1.1"
            response.headers.set("Connection", "keep-alive" if keep_alive else "close", override=False)

            await write(writer, serialize_response(response))

            if not keep_alive:
                break

    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
