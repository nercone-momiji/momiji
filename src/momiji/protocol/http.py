from __future__ import annotations

import asyncio
import ipaddress
import puremagic
from async_lru import alru_cache
from typing import TYPE_CHECKING, Iterable, Literal
from dataclasses import dataclass, field

import h11
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ConnectionTerminated, DataReceived, RequestReceived, StreamEnded

import gzip
import zlib
import zstandard
import brotlicffi

import minify_html as rhtmin
import rjsmin
import rcssmin
from scour import scour

from ..config import Config
from .tls import TLSInfo, extract_tls_info

if TYPE_CHECKING:
    from ..app import App
    from .quic import QUICInfo

class Headers:
    def __init__(self, headers: dict[str, str]):
        self.headers: dict[str, list[str]] = {}
        for k, v in headers.items():
            self.append(k, v)

    def __getitem__(self, key: str) -> str | None:
        return self.get(key)

    def __setitem__(self, key: str, value: str):
        self.set(key, value)

    def __iter__(self) -> dict[str, list[str]]:
        return self.headers

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

    response.headers.set("Server", "Momiji", override=False)
    response.headers.set("X-Powered-By", "Momiji", override=False)

    return response

def parse_peername(addr) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    if not addr or len(addr) < 2:
        return ipaddress.IPv4Address('127.0.0.1'), 0
    try:
        return ipaddress.ip_address(str(addr[0]).split('%')[0]), int(addr[1])
    except (ValueError, IndexError):
        return ipaddress.IPv4Address('127.0.0.1'), 0

def parse_pseudo_headers(raw_headers: Iterable[tuple]) -> tuple[str, str, Headers]:
    method = 'GET'
    path = '/'
    headers = Headers({})
    for raw_k, raw_v in raw_headers:
        k = raw_k.decode('latin-1') if isinstance(raw_k, bytes) else raw_k
        v = raw_v.decode('latin-1') if isinstance(raw_v, bytes) else raw_v
        if k == ':method':
            method = v
        elif k == ':path':
            path = v
        elif not k.startswith(':'):
            headers.append(k, v)
    return method, path, headers

async def send_simple_response_h11(connection: h11.Connection, writer: asyncio.StreamWriter, status_code: int, body: bytes) -> None:
    try:
        out = connection.send(h11.Response(status_code=status_code, headers=[("content-length", str(len(body))), ("content-type", "text/plain"), ("connection", "close")]))
        out += connection.send(h11.Data(data=body))
        out += connection.send(h11.EndOfMessage())
        writer.write(out)
        await writer.drain()
    except Exception:
        pass

async def handle_http11(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, app: App, config: Config):
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
            request_headers: Headers = Headers({})
            body_chunks: list[bytes] = []
            body_size = 0

            while True:
                event = connection.next_event()

                if event is h11.NEED_DATA:
                    try:
                        data = await asyncio.wait_for(reader.read(65536), timeout=config.request_read_timeout)
                    except asyncio.TimeoutError:
                        if method is not None:
                            await send_simple_response_h11(connection, writer, 408, b"Request Timeout")
                        return
                    except Exception:
                        return
                    if not data:
                        return
                    connection.receive_data(data)

                elif isinstance(event, h11.Request):
                    method = event.method.decode()
                    target = event.target.decode()
                    request_headers = Headers({k.decode(): v.decode() for k, v in event.headers})

                    content_length = request_headers.get("content-length")
                    if content_length is not None:
                        try:
                            if int(content_length) > config.request_max_body_size:
                                await send_simple_response_h11(connection, writer, 413, b"Payload Too Large")
                                return
                        except ValueError:
                            pass

                elif isinstance(event, h11.Data):
                    body_size += len(event.data)
                    if body_size > config.request_max_body_size:
                        await send_simple_response_h11(connection, writer, 413, b"Payload Too Large")
                        return
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
                        headers=request_headers,
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
        conn.send_headers(stream_id=stream_id, headers=[(b':status', str(response.status_code).encode()), list(response.headers.items())])
        conn.send_data(stream_id=stream_id, data=response.body or b"", end_stream=True)
        to_send = conn.data_to_send()
        if to_send:
            writer.write(to_send)
    await writer.drain()

async def handle_http2(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, app: App, config: Config):
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
                data = await asyncio.wait_for(reader.read(65536), timeout=config.request_read_timeout)
            except asyncio.TimeoutError:
                return
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
                            'body': bytearray(),
                            'body_size': 0
                        }

                        if content_length := headers.get("content-length"):
                            try:
                                if int(content_length) > config.request_max_body_size:
                                    connection.reset_stream(event.stream_id, error_code=0x3) # FLOW_CONTROL_ERROR
                                    streams.pop(event.stream_id, None)
                                    continue
                            except ValueError:
                                pass

                        if event.stream_ended is not None:
                            pending.add(event.stream_id)

                    elif isinstance(event, DataReceived):
                        connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                        if event.stream_id in streams:
                            stream = streams[event.stream_id]
                            stream['body_size'] += len(event.data)
                            if stream['body_size'] > config.request_max_body_size:
                                connection.reset_stream(event.stream_id, error_code=0x3)
                                streams.pop(event.stream_id, None)
                                continue
                            stream['body'] += event.data

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
