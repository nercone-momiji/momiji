from __future__ import annotations

import os
import ssl
import asyncio
import ipaddress
from typing import TYPE_CHECKING, Literal

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer as AioquicServer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted

from .h1 import H1
from .h2 import H2, H2WSUpgrade
from .h3 import H3, H3WSUpgrade
from .models import Listener, Request, Response
from .process import process
from .websocket import WebSocket, PerMessageDeflate, compute_accept, parse_frames
from ..tls import TLS, TLSInfo

if TYPE_CHECKING:
    from ..app import App, Middleware
    from ..config import Config

def parse_peername(transport: asyncio.BaseTransport) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    peer = transport.get_extra_info("peername")
    if not peer:
        return (ipaddress.IPv4Address("0.0.0.0"), 0)
    host, port = peer[0], peer[1]
    try:
        return (ipaddress.ip_address(host), int(port))
    except ValueError:
        return (ipaddress.IPv4Address("0.0.0.0"), int(port))

def negotiate_websocket(request: Request, app: App) -> tuple[str | None, PerMessageDeflate | None]:
    offered_raw = request.headers.get("Sec-WebSocket-Protocol") or ""
    offered = [p.strip() for p in offered_raw.split(",") if p.strip()] if offered_raw else []
    supported: list[str] = getattr(app, "websocket_subprotocols", [])
    subprotocol: str | None = next((p for p in offered if p in supported), None)

    ext_raw = request.headers.get("Sec-WebSocket-Extensions") or ""
    deflate = PerMessageDeflate.from_client_offer(ext_raw) if ext_raw else None

    return subprotocol, deflate

class H2WebSocketTransport:
    def __init__(self, h2: H2, stream_id: int, tcp_transport: asyncio.Transport):
        self.h2 = h2
        self.stream_id = stream_id
        self.tcp = tcp_transport

    def write(self, data: bytes) -> None:
        if self.tcp.is_closing():
            return
        out = self.h2.ws_send(self.stream_id, data)
        if out:
            self.tcp.write(out)

    def close(self) -> None:
        out = self.h2.ws_close(self.stream_id)
        if out and not self.tcp.is_closing():
            self.tcp.write(out)

class H3WebSocketTransport:
    def __init__(self, h3: H3, stream_id: int, protocol: H3Protocol):
        self.h3 = h3
        self.stream_id = stream_id
        self.protocol = protocol

    def write(self, data: bytes) -> None:
        if not data:
            return
        self.h3.ws_send(self.stream_id, data)
        self.protocol.transmit()

    def close(self) -> None:
        self.h3.ws_close(self.stream_id)
        self.protocol.transmit()

class TCPProtocol(asyncio.Protocol):
    def __init__(self, handler: Handler):
        self.handler = handler
        self.transport: asyncio.Transport | None = None
        self.h2: H2 | None = None
        self.buffer = bytearray()
        self.client: tuple = (ipaddress.IPv4Address("0.0.0.0"), 0)
        self.scheme: Literal["http", "https"] = "http"
        self.secure: bool = False
        self.tls: TLSInfo | None = None
        self.keep_alive: bool = True
        self.ws: WebSocket | None = None
        self.ws_buffer: bytearray = bytearray()
        self.keepalive_handle: asyncio.TimerHandle | None = None

    def reset_keepalive(self) -> None:
        if self.keepalive_handle is not None:
            self.keepalive_handle.cancel()
            self.keepalive_handle = None
        if self.transport is not None and self.keep_alive and self.ws is None:
            self.keepalive_handle = asyncio.get_running_loop().call_later(self.handler.config.keepalive_timeout, self.on_keepalive_timeout)

    def on_keepalive_timeout(self) -> None:
        self.keepalive_handle = None
        if self.transport is not None and not self.transport.is_closing():
            self.transport.close()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport
        self.client = parse_peername(transport)

        if self.handler.shutdown:
            transport.close()
            return

        if isinstance(transport, asyncio.Transport):
            self.handler.active_connections.add(transport)

        ssl_object: ssl.SSLObject | None = transport.get_extra_info("ssl_object")
        if ssl_object is not None:
            self.secure = True
            self.scheme = "https"
            self.tls = TLS.extract_tls_info(ssl_object)

            alpn = ssl_object.selected_alpn_protocol()
            if alpn == "h2" and "h2" in self.handler.config.protocols:
                self.h2 = H2(connection_id=os.urandom(8))
                self.transport.write(self.h2.initiate())

            elif "http/1.1" not in self.handler.config.protocols:
                self.transport.close()
                return

        else:
            self.secure = self.handler.listener.kind == "https"
            self.scheme = "https" if self.secure else "http"

        self.reset_keepalive()

    def data_received(self, data: bytes) -> None:
        if self.transport is None:
            return

        self.reset_keepalive()

        if self.ws is not None:
            self.ws_buffer.extend(data)
            for frame in parse_frames(self.ws_buffer):
                self.ws.feed_frame(frame)
            return

        if self.h2 is None and "http/1.1" not in self.handler.config.protocols:
            self.transport.close()
            return

        if self.h2 is not None:
            out, requests, ws_upgrades, closed = self.h2.receive(data, client=self.client, scheme=self.scheme, secure=self.secure, tls=self.tls)
            if out:
                self.transport.write(out)

            for request in requests:
                self.handler.create_task(self.respond_h2(request))

            for ws_upgrade in ws_upgrades:
                self.handler.create_task(self.respond_ws_h2(ws_upgrade))

            if closed:
                goaway = self.h2.close()
                if goaway:
                    self.transport.write(goaway)
                self.transport.close()

            return

        self.buffer.extend(data)
        while True:
            head_end = self.buffer.find(b"\r\n\r\n")
            if head_end == -1:
                return

            body_start = head_end + 4

            transfer_encoding_raw = b""
            content_length_raw: bytes | None = None
            for line in bytes(self.buffer[:head_end]).split(b"\r\n")[1:]:
                name_b, sep_b, value_b = line.partition(b":")
                if not sep_b:
                    continue
                name_lower = name_b.strip().lower()
                if name_lower == b"transfer-encoding":
                    transfer_encoding_raw = value_b.strip().lower()
                elif name_lower == b"content-length":
                    content_length_raw = value_b.strip()

            if b"chunked" in transfer_encoding_raw:
                scan = H1.scan_chunked(bytes(self.buffer[body_start:]))
                if scan is None:
                    return
                consumed = body_start + scan[1]

            elif content_length_raw is not None:
                try:
                    expected = int(content_length_raw)
                except ValueError:
                    self.transport.close()
                    return
                if len(self.buffer) - body_start < expected:
                    return
                consumed = body_start + expected

            else:
                consumed = body_start

            try:
                request = H1.parse(bytes(self.buffer[:consumed]), client=self.client, scheme=self.scheme, secure=self.secure, tls=self.tls)
            except (ValueError, UnicodeDecodeError):
                self.transport.close()
                return

            del self.buffer[:consumed]

            connection_token = (request.headers.get("Connection") or "").lower()
            self.keep_alive = connection_token != "close"
            self.handler.create_task(self.respond_h1(request))

            if not self.keep_alive:
                return

    async def respond_h1(self, request: Request) -> None:
        if self.transport is None:
            return

        upgrade = (request.headers.get("Upgrade", "")).lower().strip()
        connection = (request.headers.get("Connection", "")).lower()

        ws_key = (request.headers.get("Sec-WebSocket-Key", "")).strip()
        ws_version = (request.headers.get("Sec-WebSocket-Version", "")).strip()

        if upgrade == "websocket" and "upgrade" in connection and ws_key and ws_version == "13":
            if self.handler.shutdown:
                self.transport.write(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                self.transport.close()
                return
            await self.upgrade_websocket(request, ws_key)
            return

        response = await process(self.handler.app, request, middlewares=self.handler.middlewares)

        if self.handler.shutdown:
            response.headers.set("Connection", "close")
            self.keep_alive = False

        if "h3" in self.handler.config.protocols and self.handler.config.bind_quic:
            _, _, h3_port = self.handler.config.bind_quic[0].rpartition(':')
            response.headers.set("Alt-Svc", f"h3=\":{int(h3_port)}\"", override=False)

        if response.is_streaming:
            await self.stream_h1(response)
            return

        result = H1.build(response)

        if isinstance(result, tuple):
            head, alt_body = result
            self.transport.write(head)

            if alt_body is not None:
                await self.send_file_h1(alt_body, response.file_range)

        else:
            self.transport.write(result)

        if not self.keep_alive:
            self.transport.close()

    async def stream_h1(self, response: Response) -> None:
        if self.transport is None:
            return

        self.transport.write(H1.build_head(response))

        try:
            async for chunk in response.body:
                if chunk and self.transport is not None:
                    self.transport.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")

        finally:
            if self.transport is not None:
                self.transport.write(b"0\r\n\r\n")
                if not self.keep_alive:
                    self.transport.close()

    async def upgrade_websocket(self, request: Request, ws_key: str) -> None:
        if self.transport is None:
            return

        subprotocol, deflate = negotiate_websocket(request, self.handler.app)
        accept = compute_accept(ws_key)

        lines = [
            b"HTTP/1.1 101 Switching Protocols\r\n",
            b"Upgrade: websocket\r\n",
            b"Connection: Upgrade\r\n",
            b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n"
        ]
        if subprotocol:
            lines.append(b"Sec-WebSocket-Protocol: " + subprotocol.encode() + b"\r\n")
        if deflate is not None:
            lines.append(b"Sec-WebSocket-Extensions: " + deflate.response_header().encode() + b"\r\n")
        lines.append(b"\r\n")

        self.transport.write(b"".join(lines))
        ws = WebSocket(self.transport, subprotocol=subprotocol, deflate=deflate)
        self.ws = ws
        self.ws_buffer = bytearray()
        self.handler.create_task(self.run_websocket(request, ws))

    async def run_websocket(self, request: Request, ws: WebSocket) -> None:
        self.handler.active_ws.add(ws)
        try:
            for middleware in self.handler.middlewares:
                result = await middleware.on_websocket(request, ws)
                if result is None:
                    continue
                request, ws = result
            await self.handler.app.on_websocket(request, ws)
        except Exception:
            pass
        finally:
            self.handler.active_ws.discard(ws)
            if not ws.closed:
                await ws.close(1011)

    async def send_file_h1(self, path: os.PathLike, file_range: tuple[int, int] | None = None) -> None:
        if self.transport is None:
            return
        loop = asyncio.get_running_loop()

        def read_chunks() -> list[bytes]:
            chunks: list[bytes] = []

            with open(os.fspath(path), "rb") as fp:
                if file_range is not None:
                    start, end = file_range
                    fp.seek(start)
                    remaining = end - start + 1
                    while remaining > 0:
                        chunk = fp.read(min(65536, remaining))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)

                else:
                    while True:
                        chunk = fp.read(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)

            return chunks

        for chunk in await loop.run_in_executor(None, read_chunks):
            self.transport.write(chunk)

    async def respond_h2(self, request: Request) -> None:
        if self.transport is None or self.h2 is None or request.h2 is None:
            return

        response = await process(self.handler.app, request, middlewares=self.handler.middlewares)

        if "h3" in self.handler.config.protocols and self.handler.config.bind_quic:
            _, _, h3_port = self.handler.config.bind_quic[0].rpartition(':')
            response.headers.set("Alt-Svc", f"h3=\":{int(h3_port)}\"", override=False)

        if response.is_streaming:
            await self.stream_h2(request.h2.stream_id, response)
            return

        out, alt_body = self.h2.send(request.h2.stream_id, response)

        if out:
            self.transport.write(out)

        if alt_body is not None:
            await self.send_file_h2(request.h2.stream_id, alt_body, response.file_range)

    async def stream_h2(self, stream_id: int, response: Response) -> None:
        if self.transport is None or self.h2 is None:
            return

        out = self.h2.send_headers(stream_id, response)
        if out:
            self.transport.write(out)

        try:
            async for chunk in response.body:
                if chunk and self.transport is not None and self.h2 is not None:
                    out = self.h2.send_chunk(stream_id, chunk, end_stream=False)
                    if out:
                        self.transport.write(out)

        finally:
            if self.h2 is not None and self.transport is not None:
                out = self.h2.send_chunk(stream_id, b"", end_stream=True)
                if out:
                    self.transport.write(out)

    async def respond_ws_h2(self, upgrade: H2WSUpgrade) -> None:
        if self.transport is None or self.h2 is None:
            return

        subprotocol, deflate = negotiate_websocket(upgrade.request, self.handler.app)

        out = self.h2.ws_accept(upgrade.stream_id, subprotocol=subprotocol, extensions=deflate.response_header() if deflate is not None else None)
        if out:
            self.transport.write(out)

        ws_transport = H2WebSocketTransport(self.h2, upgrade.stream_id, self.transport)
        ws = WebSocket(ws_transport, require_masking=False, subprotocol=subprotocol, deflate=deflate)

        self.handler.create_task(self.read_ws_h2(upgrade.stream_id, ws))
        await self.run_websocket(upgrade.request, ws)

    async def read_ws_h2(self, stream_id: int, ws: WebSocket) -> None:
        if self.h2 is None:
            return

        queue = self.h2.ws_streams.get(stream_id)
        if queue is None:
            return

        buf = bytearray()

        while True:
            chunk = await queue.get()
            if chunk is None:
                ws.queue.put_nowait(None)
                break

            buf.extend(chunk)
            for frame in parse_frames(buf):
                ws.feed_frame(frame)

    async def send_file_h2(self, stream_id: int, path: os.PathLike, file_range: tuple[int, int] | None = None) -> None:
        if self.transport is None or self.h2 is None:
            return
        loop = asyncio.get_running_loop()

        def read_chunks() -> list[bytes]:
            chunks: list[bytes] = []

            with open(os.fspath(path), "rb") as fp:
                if file_range is not None:
                    start, end = file_range
                    fp.seek(start)
                    remaining = end - start + 1
                    while remaining > 0:
                        chunk = fp.read(min(65536, remaining))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)

                else:
                    while True:
                        chunk = fp.read(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)

            return chunks

        chunks = await loop.run_in_executor(None, read_chunks)
        for i, chunk in enumerate(chunks):
            out = self.h2.send_chunk(stream_id, chunk, end_stream=(i == len(chunks) - 1))
            if out and self.transport:
                self.transport.write(out)
        if not chunks:
            out = self.h2.send_chunk(stream_id, b"", end_stream=True)
            if out and self.transport:
                self.transport.write(out)

    def connection_lost(self, exc: BaseException | None) -> None:
        if self.keepalive_handle is not None:
            self.keepalive_handle.cancel()
            self.keepalive_handle = None

        transport = self.transport
        self.transport = None

        if transport is not None:
            self.handler.active_connections.discard(transport)

        if self.h2 is not None:
            for queue in self.h2.ws_streams.values():
                queue.put_nowait(None)
            self.h2 = None

        if self.ws is not None and not self.ws.closed:
            self.ws.queue.put_nowait(None)

        self.buffer.clear()

class H3Protocol(QuicConnectionProtocol):
    def __init__(self, *args, handler: Handler, **kwargs):
        super().__init__(*args, **kwargs)
        self.handler = handler
        self.h3: H3 | None = None
        self.client: tuple = (ipaddress.IPv4Address("0.0.0.0"), 0)
        self.tls: TLSInfo | None = None

    def quic_event_received(self, event) -> None:
        if isinstance(event, HandshakeCompleted) and self.tls is None:
            self.tls = TLS.extract_tls_info_h3(self._quic)

        if self.h3 is None:
            self.h3 = H3(self._quic, connection_id=self._quic.host_cid)
            self.client = parse_peername(self._transport)

        requests, ws_upgrades = self.h3.handle_event(event, client=self.client, scheme="https", secure=True, tls=self.tls)

        for request in requests:
            self.handler.create_task(self.respond(request))

        for ws_upgrade in ws_upgrades:
            self.handler.create_task(self.ws_response_h3(ws_upgrade))

    async def respond(self, request: Request) -> None:
        if self.h3 is None or request.h3 is None:
            return

        response = await process(self.handler.app, request, middlewares=self.handler.middlewares)

        if response.is_streaming:
            await self.stream_h3(request.h3.stream_id, response)
            return

        alt_body = self.h3.send(request.h3.stream_id, response)

        if alt_body is not None:
            await self.send_file(request.h3.stream_id, alt_body, response.file_range)

        else:
            self.transmit()

    async def stream_h3(self, stream_id: int, response: Response) -> None:
        if self.h3 is None:
            return

        self.h3.send_headers_only(stream_id, response)
        self.transmit()

        try:
            async for chunk in response.body:
                if chunk and self.h3 is not None:
                    self.h3.send_chunk(stream_id, chunk, end_stream=False)
                    self.transmit()

        finally:
            if self.h3 is not None:
                self.h3.send_chunk(stream_id, b"", end_stream=True)
                self.transmit()

    async def ws_response_h3(self, upgrade: H3WSUpgrade) -> None:
        if self.h3 is None:
            return

        subprotocol, deflate = negotiate_websocket(upgrade.request, self.handler.app)

        self.h3.ws_accept(upgrade.stream_id, subprotocol=subprotocol, extensions=deflate.response_header() if deflate is not None else None)
        self.transmit()

        ws_transport = H3WebSocketTransport(self.h3, upgrade.stream_id, self)
        ws = WebSocket(ws_transport, require_masking=False, subprotocol=subprotocol, deflate=deflate)

        self.handler.create_task(self.ws_read_h3(upgrade.stream_id, ws))

        request = upgrade.request
        self.handler.active_ws.add(ws)
        try:
            for middleware in self.handler.middlewares:
                result = await middleware.on_websocket(request, ws)
                if result is None:
                    continue
                request, ws = result
            await self.handler.app.on_websocket(request, ws)

        except Exception:
            pass

        finally:
            self.handler.active_ws.discard(ws)
            if not ws.closed:
                await ws.close(1011)

    async def ws_read_h3(self, stream_id: int, ws: WebSocket) -> None:
        if self.h3 is None:
            return

        queue = self.h3.ws_streams.get(stream_id)
        if queue is None:
            return

        buf = bytearray()
        while True:
            chunk = await queue.get()
            if chunk is None:
                ws.queue.put_nowait(None)
                break

            buf.extend(chunk)

            for frame in parse_frames(buf):
                ws.feed_frame(frame)

    async def send_file(self, stream_id: int, path: os.PathLike, file_range: tuple[int, int] | None = None) -> None:
        if self.h3 is None:
            return
        loop = asyncio.get_running_loop()

        def read_chunks() -> list[bytes]:
            chunks: list[bytes] = []

            with open(os.fspath(path), "rb") as fp:
                if file_range is not None:
                    start, end = file_range
                    fp.seek(start)
                    remaining = end - start + 1
                    while remaining > 0:
                        chunk = fp.read(min(65536, remaining))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)

                else:
                    while True:
                        chunk = fp.read(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)

            return chunks

        chunks = await loop.run_in_executor(None, read_chunks)
        for i, chunk in enumerate(chunks):
            self.h3.send_chunk(stream_id, chunk, end_stream=(i == len(chunks) - 1))
            self.transmit()
        if not chunks:
            self.h3.send_chunk(stream_id, b"", end_stream=True)
            self.transmit()

class Handler:
    def __init__(self, listener: Listener, app: App, middlewares: list[Middleware], config: Config):
        self.listener = listener
        self.app = app
        self.middlewares = middlewares
        self.config = config
        self.tcp_server: asyncio.base_events.Server | None = None
        self.quic_server = None
        self.shutdown = False
        self.active_tasks: set[asyncio.Task] = set()
        self.active_ws: set[WebSocket] = set()
        self.active_connections: set[asyncio.Transport] = set()

    def create_task(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self.active_tasks.add(task)
        task.add_done_callback(self.active_tasks.discard)
        return task

    async def drain(self, timeout: float) -> None:
        self.shutdown = True

        if self.tcp_server is not None:
            self.tcp_server.close()

        for ws in list(self.active_ws):
            if not ws.closed:
                try:
                    await ws.close(1001, "Server shutdown")
                except Exception:
                    pass

        tasks = list(self.active_tasks)
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=timeout)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

        for transport in list(self.active_connections):
            if not transport.is_closing():
                transport.close()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        kind = self.listener.kind

        if kind in ("http", "unix"):
            self.tcp_server = await loop.create_server(lambda: TCPProtocol(self), sock=self.listener.sock)

        elif kind == "https":
            ssl_context = TLS.create_ssl_context(self.config)
            self.tcp_server = await loop.create_server(lambda: TCPProtocol(self), sock=self.listener.sock, ssl=ssl_context)

        elif kind == "quic":
            quic_config = QuicConfiguration(is_client=False, alpn_protocols=["h3"], max_datagram_frame_size=65536)
            if self.config.tls.certfile:
                quic_config.load_cert_chain(self.config.tls.certfile, self.config.tls.keyfile)

            _, self.quic_server = await loop.create_datagram_endpoint(lambda: AioquicServer(configuration=quic_config, create_protocol=lambda *a, **kw: H3Protocol(*a, handler=self, **kw)), sock=self.listener.sock)

        else:
            raise ValueError(f"unsupported listener kind: {kind!r}")

    async def stop(self) -> None:
        if self.tcp_server is not None:
            self.tcp_server.close()
            try:
                await self.tcp_server.wait_closed()
            except Exception:
                pass
            self.tcp_server = None
        if self.quic_server is not None:
            self.quic_server.close()
            self.quic_server = None
