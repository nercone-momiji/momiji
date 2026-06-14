from __future__ import annotations

import os
import gzip
import zlib
import asyncio
import functools
import ipaddress
import zstandard
import brotlicffi
from typing import TYPE_CHECKING, Iterable, Literal
from dataclasses import dataclass, field

import h11
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ConnectionTerminated, DataReceived, RequestReceived, StreamEnded

from .tls import TLSInfo, extract_tls_info

if TYPE_CHECKING:
    from ..app import App
    from .quic import QUICInfo

@dataclass
class Request:
    client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]
    scheme: Literal["http", "https"]
    secure: bool

    protocol: Literal["HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]
    method: Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
    target: str
    headers: dict[str, str]
    body: bytes | None

    tls: TLSInfo | None
    quic: QUICInfo | None

@dataclass
class Response:
    body: bytes | os.PathLike | None = None
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    compression: bool = True

@functools.lru_cache(maxsize=128)
async def compress_zstd(body: bytes) -> bytes:
    return zstandard.ZstdCompressor(level=3).compress(body)

@functools.lru_cache(maxsize=128)
async def compress_brotli(body: bytes) -> bytes:
    return brotlicffi.compress(body, quality=4)

@functools.lru_cache(maxsize=128)
async def compress_gzip(body: bytes) -> bytes:
    return gzip.compress(body, compresslevel=6)

@functools.lru_cache(maxsize=128)
async def compress_deflate(body: bytes) -> bytes:
    return zlib.compress(body, level=6)

async def compress(type: Literal["zstd", "br", "gzip", "deflate"], body: bytes) -> bytes:
    if type == "zstd":
        return await compress_zstd(body)
    elif type == "br":
        return await compress_brotli(body)
    elif type == "gzip":
        return await compress_gzip(body)
    elif type == "deflate":
        return await compress_deflate(body)

async def process(app: App, request: Request) -> Response:
    try:
        response = app(request)
        response.headers = {k.lower(): v for k, v in response.headers.items()}
    except Exception:
        response = Response(b"Internal Server Error", status_code=500)

    def set_header(key: str, value: str, override: bool = False):
        if override or key.lower() not in response.headers:
            response.headers[key.lower()] = value

    compressed = False
    if response.compression:
        for encoding in ["zstd", "br", "gzip", "deflate"]:
            compressed = True
            response.body = await compress(encoding, response.body)
            set_header("Content-Encoding", encoding, True)

    set_header("Content-Length", str(len(response.body)), compressed)

    set_header("Server",       "Momiji")
    set_header("X-Powered-By", "Momiji")

    return response

def parse_peername(addr) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    if not addr or len(addr) < 2:
        return ipaddress.IPv4Address('127.0.0.1'), 0
    try:
        return ipaddress.ip_address(str(addr[0]).split('%')[0]), int(addr[1])
    except (ValueError, IndexError):
        return ipaddress.IPv4Address('127.0.0.1'), 0

def parse_pseudo_headers(raw_headers: Iterable[tuple]) -> tuple[str, str, dict[str, str]]:
    method = 'GET'
    path = '/'
    headers: dict[str, str] = {}
    for raw_k, raw_v in raw_headers:
        k = raw_k.decode('latin-1') if isinstance(raw_k, bytes) else raw_k
        v = raw_v.decode('latin-1') if isinstance(raw_v, bytes) else raw_v
        if k == ':method':
            method = v
        elif k == ':path':
            path = v
        elif not k.startswith(':'):
            headers[k] = v
    return method, path, headers

async def handle_http11(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, app: App):
    connection = h11.Connection(our_role=h11.SERVER)
    client = parse_peername(writer.get_extra_info('peername'))
    ssl_object = writer.get_extra_info('ssl_object')
    secure = ssl_object is not None
    scheme = 'https' if secure else 'http'
    tls = extract_tls_info(ssl_object)

    try:
        while True:
            method: str | None = None
            target: str | None = None
            request_headers: dict[str, str] | None = None
            body_chunks: list[bytes] = []

            while True:
                event = connection.next_event()

                if event is h11.NEED_DATA:
                    try:
                        data = await reader.read(65536)
                    except Exception:
                        return
                    if not data:
                        return
                    connection.receive_data(data)

                elif isinstance(event, h11.Request):
                    method = event.method.decode()
                    target = event.target.decode()
                    request_headers = {k.decode().lower(): v.decode() for k, v in event.headers}

                elif isinstance(event, h11.Data):
                    body_chunks.append(event.data)

                elif isinstance(event, h11.EndOfMessage):
                    if method is None:
                        return

                    request = Request(
                        client=client,
                        scheme=scheme,
                        secure=secure,
                        protocol='HTTP/1.1',
                        method=method,
                        target=target or '/',
                        headers=request_headers or {},
                        body=b''.join(body_chunks) or None,
                        tls=tls,
                        quic=None
                    )
                    response = await process(app, request)

                    out = connection.send(h11.Response(status_code=response.status_code, headers=list(response.headers.items())))
                    if response.body:
                        out += connection.send(h11.Data(data=response.body))
                    out += connection.send(h11.EndOfMessage())
                    writer.write(out)
                    await writer.drain()

                    if connection.our_state is h11.DONE and connection.their_state is h11.DONE:
                        connection.start_next_cycle()
                        break
                    return

                elif isinstance(event, h11.ConnectionClosed):
                    return

                elif event is h11.PAUSED:
                    return

    except Exception:
        pass

    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def respond_http2(conn: H2Connection, writer: asyncio.StreamWriter, lock: asyncio.Lock, stream_id: int, request: Request, app: App):
    response = await process(app, request)

    async with lock:
        conn.send_headers(stream_id=stream_id, headers=list(response.headers.items()))
        conn.send_data(stream_id=stream_id, data=response.body, end_stream=True)
        to_send = conn.data_to_send()
        if to_send:
            writer.write(to_send)
    await writer.drain()

async def handle_http2(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, app: App):
    client = parse_peername(writer.get_extra_info('peername'))
    tls = extract_tls_info(writer.get_extra_info('ssl_object'))

    config = H2Configuration(client_side=False, header_encoding='utf-8')
    connection = H2Connection(config=config)
    lock = asyncio.Lock()

    async with lock:
        connection.initiate_connection()
        writer.write(connection.data_to_send())
        await writer.drain()

    streams: dict[int, dict] = {}
    tasks: set[asyncio.Task] = set()
    pending: set[int] = set()

    def dispatch(stream_id: int):
        stream = streams.pop(stream_id)
        request = Request(
            client=client,
            scheme='https',
            secure=True,
            protocol='HTTP/2.0',
            method=stream['method'],
            target=stream['path'],
            headers=stream['headers'],
            body=bytes(stream['body']) if stream['body'] else None,
            tls=tls,
            quic=None
        )
        t = asyncio.create_task(respond_http2(connection, writer, lock, stream_id, request, app))
        tasks.add(t)
        t.add_done_callback(tasks.discard)

    try:
        while True:
            try:
                data = await reader.read(65536)
            except Exception:
                return
            if not data:
                break

            pending.clear()

            async with lock:
                events = connection.receive_data(data)
                for event in events:
                    if isinstance(event, RequestReceived):
                        method, path, headers = parse_pseudo_headers(event.headers)
                        streams[event.stream_id] = {
                            'method': method,
                            'path': path,
                            'headers': headers,
                            'body': bytearray()
                        }
                        if event.stream_ended is not None:
                            pending.add(event.stream_id)

                    elif isinstance(event, DataReceived):
                        connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                        if event.stream_id in streams:
                            streams[event.stream_id]['body'] += event.data

                        if event.stream_ended is not None and event.stream_id in streams:
                            pending.add(event.stream_id)

                    elif isinstance(event, StreamEnded):
                        if event.stream_id in streams:
                            pending.add(event.stream_id)

                    elif isinstance(event, ConnectionTerminated):
                        return

                to_send = connection.data_to_send()
                if to_send:
                    writer.write(to_send)
            if to_send:
                await writer.drain()

            for sid in pending:
                if sid in streams:
                    dispatch(sid)

    except Exception:
        pass

    finally:
        for t in tasks:
            t.cancel()

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def handle_https(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, app: App):
    ssl_object = writer.get_extra_info('ssl_object')
    if ssl_object is not None and ssl_object.selected_alpn_protocol() == 'h2':
        await handle_http2(reader, writer, app)
    else:
        await handle_http11(reader, writer, app)
