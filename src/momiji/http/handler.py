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
from .h2 import H2
from .h3 import H3
from .models import Listener, Request
from .process import process
from ..tls import TLS, TLSInfo

if TYPE_CHECKING:
    from ..app import App
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

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport
        self.client = parse_peername(transport)

        ssl_object: ssl.SSLObject | None = transport.get_extra_info("ssl_object")
        if ssl_object is not None:
            self.secure = True
            self.scheme = "https"
            self.tls = TLS.extract_tls_info(ssl_object)
            alpn = ssl_object.selected_alpn_protocol()
            if alpn == "h2" and "h2" in self.handler.config.protocols:
                self.h2 = H2()
                self.transport.write(self.h2.initiate())
            elif "http/1.1" not in self.handler.config.protocols:
                self.transport.close()
                return
        else:
            self.secure = self.handler.listener.kind == "https"
            self.scheme = "https" if self.secure else "http"

    def data_received(self, data: bytes) -> None:
        if self.transport is None:
            return

        if self.h2 is None and "http/1.1" not in self.handler.config.protocols:
            self.transport.close()
            return

        if self.h2 is not None:
            out, requests, closed = self.h2.receive(data, client=self.client, scheme=self.scheme, secure=self.secure, tls=self.tls)
            if out:
                self.transport.write(out)
            for request in requests:
                asyncio.create_task(self.respond_h2(request))
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
            asyncio.create_task(self.respond_h1(request))

            if not self.keep_alive:
                return

    async def respond_h1(self, request: Request) -> None:
        if self.transport is None:
            return

        response = await process(self.handler.app, request)

        if "h3" in self.handler.config.protocols and self.handler.config.bind_quic:
            _, _, h3_port = self.handler.config.bind_quic[0].rpartition(':')
            response.headers.set("Alt-Svc", f"h3=\":{int(h3_port)}\"", override=False)

        result = H1.build(response)

        if isinstance(result, tuple):
            head, alt_body = result
            self.transport.write(head)

            if alt_body is not None:
                await self.send_file_h1(alt_body)

        else:
            self.transport.write(result)

        if not self.keep_alive:
            self.transport.close()

    async def send_file_h1(self, path: os.PathLike) -> None:
        if self.transport is None:
            return
        loop = asyncio.get_running_loop()

        def read_chunks() -> list[bytes]:
            chunks: list[bytes] = []
            with open(os.fspath(path), "rb") as fp:
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

        response = await process(self.handler.app, request)

        if "h3" in self.handler.config.protocols and self.handler.config.bind_quic:
            _, _, h3_port = self.handler.config.bind_quic[0].rpartition(':')
            response.headers.set("Alt-Svc", f"h3=\":{int(h3_port)}\"", override=False)

        out, alt_body = self.h2.send(request.h2.stream_id, response)

        if out:
            self.transport.write(out)

        if alt_body is not None:
            await self.send_file_h2(request.h2.stream_id, alt_body)

    async def send_file_h2(self, stream_id: int, path: os.PathLike) -> None:
        if self.transport is None or self.h2 is None:
            return
        loop = asyncio.get_running_loop()

        def read_chunks() -> list[bytes]:
            chunks: list[bytes] = []
            with open(os.fspath(path), "rb") as fp:
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
        self.transport = None
        self.h2 = None
        self.buffer.clear()

class H3Protocol(QuicConnectionProtocol):
    def __init__(self, *args, handler: Handler, **kwargs):
        super().__init__(*args, **kwargs)
        self.handler = handler
        self.h3: H3 | None = None
        self._client: tuple = (ipaddress.IPv4Address("0.0.0.0"), 0)
        self._tls: TLSInfo | None = None

    def quic_event_received(self, event) -> None:
        if isinstance(event, HandshakeCompleted) and self._tls is None:
            self._tls = TLS.extract_tls_info_h3(self._quic)

        if self.h3 is None:
            self.h3 = H3(self._quic, connection_id=self._quic.host_cid)
            self._client = parse_peername(self._transport)

        for request in self.h3.handle_event(event, client=self._client, scheme="https", secure=True, tls=self._tls):
            asyncio.create_task(self.respond(request))

    async def respond(self, request: Request) -> None:
        if self.h3 is None or request.h3 is None:
            return

        response = await process(self.handler.app, request)

        alt_body = self.h3.send(request.h3.stream_id, response)

        if alt_body is not None:
            await self.send_file(request.h3.stream_id, alt_body)

        else:
            self.transmit()

    async def send_file(self, stream_id: int, path: os.PathLike) -> None:
        if self.h3 is None:
            return
        loop = asyncio.get_running_loop()

        def read_chunks() -> list[bytes]:
            chunks: list[bytes] = []
            with open(os.fspath(path), "rb") as fp:
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
    def __init__(self, listener: Listener, app: App, config: Config):
        self.listener = listener
        self.app = app
        self.config = config
        self.tcp_server: asyncio.base_events.Server | None = None
        self.quic_server = None

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
            await self.tcp_server.wait_closed()
            self.tcp_server = None
        if self.quic_server is not None:
            self.quic_server.close()
            self.quic_server = None
