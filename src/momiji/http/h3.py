from __future__ import annotations

import os
import asyncio
import ipaddress
from typing import Literal
from dataclasses import dataclass, field

from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.connection import QuicConnection

from .models import Request, Response, Headers
from ..tls import TLSInfo

@dataclass
class H3Info:
    connection_id: bytes
    stream_id: int

@dataclass
class H3WSUpgrade:
    stream_id: int
    request: Request

@dataclass
class Stream:
    method: str = ""
    target: str = ""
    scheme: str = "https"
    authority: str = ""
    headers: Headers = field(default_factory=lambda: Headers({}))
    body: bytearray = field(default_factory=bytearray)

class H3:
    def __init__(self, quic: QuicConnection, connection_id: bytes = b"", max_body_size: int = 16 * 1024 * 1024):
        self.connection_id = connection_id
        self.quic = quic
        self.connection = H3Connection(quic)
        self.streams: dict[int, Stream] = {}
        self.ws_streams: dict[int, asyncio.Queue[bytes | None]] = {}
        self.max_body_size = max_body_size

    def receive(self, *, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], scheme: Literal["http", "https"] = "https", secure: bool = True, tls: TLSInfo | None = None) -> tuple[list[Request], list[H3WSUpgrade]]:
        completed: list[Request] = []
        ws_upgrades: list[H3WSUpgrade] = []

        while True:
            quic_event = self.quic.next_event()
            if quic_event is None:
                break
            r, ws = self.handle_event(quic_event, client=client, scheme=scheme, secure=secure, tls=tls)
            completed.extend(r)
            ws_upgrades.extend(ws)

        return completed, ws_upgrades

    def handle_event(self, quic_event, *, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], scheme: Literal["http", "https"] = "https", secure: bool = True, tls: TLSInfo | None = None) -> tuple[list[Request], list[H3WSUpgrade]]:
        completed: list[Request] = []
        ws_upgrades: list[H3WSUpgrade] = []

        for event in self.connection.handle_event(quic_event):
            if isinstance(event, HeadersReceived):
                stream = Stream(scheme=scheme)
                ws_protocol: str | None = None
                for name, value in event.headers:
                    nb = name.decode("ascii") if isinstance(name, (bytes, bytearray)) else name
                    vb = value.decode("utf-8") if isinstance(value, (bytes, bytearray)) else value
                    if nb == ":method":
                        stream.method = vb
                    elif nb == ":path":
                        stream.target = vb
                    elif nb == ":scheme":
                        stream.scheme = vb
                    elif nb == ":authority":
                        stream.authority = vb
                        stream.headers.append("host", vb)
                    elif nb == ":protocol":
                        ws_protocol = vb
                    elif not nb.startswith(":"):
                        stream.headers.append(nb, vb)

                if stream.method == "CONNECT" and ws_protocol == "websocket":
                    queue: asyncio.Queue[bytes | None] = asyncio.Queue()
                    self.ws_streams[event.stream_id] = queue
                    request = Request(client=client, scheme=stream.scheme if stream.scheme in ("http", "https") else "https", secure=secure, protocol="HTTP/3.0", method="GET", target=stream.target, headers=stream.headers, body=None, h2=None, h3=H3Info(connection_id=self.connection_id, stream_id=event.stream_id), tls=tls)
                    ws_upgrades.append(H3WSUpgrade(stream_id=event.stream_id, request=request))
                    continue

                self.streams[event.stream_id] = stream
                if event.stream_ended:
                    completed.append(self.finalize(event.stream_id, client, secure, tls))

            elif isinstance(event, DataReceived):
                if event.stream_id in self.ws_streams:
                    if event.data:
                        self.ws_streams[event.stream_id].put_nowait(event.data)

                    if event.stream_ended:
                        self.ws_streams[event.stream_id].put_nowait(None)
                        del self.ws_streams[event.stream_id]

                else:
                    stream = self.streams.get(event.stream_id)

                    if stream is not None:
                        stream.body.extend(event.data)

                    if stream is not None and len(stream.body) > self.max_body_size:
                        self.streams.pop(event.stream_id, None)
                        try:
                            self.quic.reset_stream(event.stream_id, error_code=0x10C)
                        except Exception:
                            pass

                    elif event.stream_ended and event.stream_id in self.streams:
                        completed.append(self.finalize(event.stream_id, client, secure, tls))

        return completed, ws_upgrades

    def finalize(self, stream_id: int, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], secure: bool, tls: TLSInfo | None) -> Request:
        stream = self.streams.pop(stream_id)
        body = bytes(stream.body) if stream.body else None
        return Request(client=client, scheme=stream.scheme if stream.scheme in ("http", "https") else "https", secure=secure, protocol="HTTP/3.0", method=stream.method, target=stream.target, headers=stream.headers, body=body, h2=None, h3=H3Info(connection_id=self.connection_id, stream_id=stream_id), tls=tls)

    def send(self, stream_id: int, response: Response) -> os.PathLike | None:
        headers: list[tuple[bytes, bytes]] = [(b":status", str(response.status_code).encode("ascii"))]
        for name, value in response.headers.items():
            lname = name.lower()
            if lname in ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection"):
                continue
            headers.append((lname.encode("ascii"), value.encode("utf-8")))

        if response.has_real_body:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            self.connection.send_data(stream_id, response.body, end_stream=True)
            return None

        elif response.body is not None:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            return response.body

        else:
            self.connection.send_headers(stream_id, headers, end_stream=True)
            return None

    def send_headers_only(self, stream_id: int, response: Response) -> None:
        headers: list[tuple[bytes, bytes]] = [(b":status", str(response.status_code).encode("ascii"))]
        for name, value in response.headers.items():
            lname = name.lower()
            if lname in ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection"):
                continue
            headers.append((lname.encode("ascii"), value.encode("utf-8")))
        self.connection.send_headers(stream_id, headers, end_stream=False)

    def send_chunk(self, stream_id: int, chunk: bytes, end_stream: bool) -> None:
        self.connection.send_data(stream_id, chunk, end_stream=end_stream)

    def ws_accept(self, stream_id: int, subprotocol: str | None = None, extensions: str | None = None) -> None:
        headers: list[tuple[bytes, bytes]] = [(b":status", b"200")]
        if subprotocol:
            headers.append((b"sec-websocket-protocol", subprotocol.encode()))
        if extensions:
            headers.append((b"sec-websocket-extensions", extensions.encode()))
        self.connection.send_headers(stream_id, headers, end_stream=False)

    def ws_send(self, stream_id: int, data: bytes) -> None:
        self.connection.send_data(stream_id, data, end_stream=False)

    def ws_close(self, stream_id: int) -> None:
        self.ws_streams.pop(stream_id, None)
        try:
            self.connection.send_data(stream_id, b"", end_stream=True)
        except Exception:
            pass
