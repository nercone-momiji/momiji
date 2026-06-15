from __future__ import annotations

import os
import asyncio
import ipaddress
from typing import Literal
from dataclasses import dataclass, field

import h2.config
import h2.connection
import h2.events
from h2.settings import SettingCodes

from .models import Request, Response, Headers
from ..tls import TLSInfo

@dataclass
class H2Info:
    connection_id: bytes
    stream_id: int

@dataclass
class H2WSUpgrade:
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

class H2:
    def __init__(self, connection_id: bytes = b""):
        self.connection_id = connection_id
        self.connection = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8"))
        self.streams: dict[int, Stream] = {}
        self.ws_streams: dict[int, asyncio.Queue[bytes | None]] = {}

    def initiate(self) -> bytes:
        self.connection.initiate_connection()
        self.connection.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1})
        return self.connection.data_to_send()

    def receive(self, data: bytes, *, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], scheme: Literal["http", "https"] = "https", secure: bool = True, tls: TLSInfo | None = None) -> tuple[bytes, list[Request], list[H2WSUpgrade], bool]:
        closed = False
        events = self.connection.receive_data(data)
        completed: list[Request] = []
        ws_upgrades: list[H2WSUpgrade] = []

        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                stream = Stream(scheme=scheme)
                ws_protocol: str | None = None
                for name, value in event.headers:
                    if name == ":method":
                        stream.method = value
                    elif name == ":path":
                        stream.target = value
                    elif name == ":scheme":
                        stream.scheme = value
                    elif name == ":authority":
                        stream.authority = value
                        stream.headers.append("host", value)
                    elif name == ":protocol":
                        ws_protocol = value
                    elif not name.startswith(":"):
                        stream.headers.append(name, value)

                if stream.method == "CONNECT" and ws_protocol == "websocket":
                    queue: asyncio.Queue[bytes | None] = asyncio.Queue()
                    self.ws_streams[event.stream_id] = queue
                    request = Request(client=client, scheme=stream.scheme if stream.scheme in ("http", "https") else "https", secure=secure, protocol="HTTP/2.0", method="GET", target=stream.target, headers=stream.headers, body=None, h2=H2Info(connection_id=self.connection_id, stream_id=event.stream_id), h3=None, tls=tls)
                    ws_upgrades.append(H2WSUpgrade(stream_id=event.stream_id, request=request))
                    continue

                self.streams[event.stream_id] = stream
                if event.stream_ended:
                    completed.append(self.finalize(event.stream_id, client, secure, tls))

            elif isinstance(event, h2.events.DataReceived):
                if event.stream_id in self.ws_streams:
                    if event.data:
                        self.ws_streams[event.stream_id].put_nowait(event.data)
                    self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    if event.stream_ended:
                        self.ws_streams[event.stream_id].put_nowait(None)
                        del self.ws_streams[event.stream_id]

                else:
                    stream = self.streams.get(event.stream_id)
                    if stream is not None:
                        stream.body.extend(event.data)
                    self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    if event.stream_ended and event.stream_id in self.streams:
                        completed.append(self.finalize(event.stream_id, client, secure, tls))

            elif isinstance(event, h2.events.StreamEnded):
                if event.stream_id in self.ws_streams:
                    self.ws_streams[event.stream_id].put_nowait(None)
                    del self.ws_streams[event.stream_id]
                elif event.stream_id in self.streams:
                    completed.append(self.finalize(event.stream_id, client, secure, tls))

            elif isinstance(event, h2.events.StreamReset):
                if event.stream_id in self.ws_streams:
                    self.ws_streams[event.stream_id].put_nowait(None)
                    del self.ws_streams[event.stream_id]
                else:
                    self.streams.pop(event.stream_id, None)

            elif isinstance(event, h2.events.ConnectionTerminated):
                for queue in self.ws_streams.values():
                    queue.put_nowait(None)
                self.ws_streams.clear()
                self.streams.clear()
                closed = True

        return self.connection.data_to_send(), completed, ws_upgrades, closed

    def finalize(self, stream_id: int, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], secure: bool, tls: TLSInfo | None) -> Request:
        stream = self.streams.pop(stream_id)
        body = bytes(stream.body) if stream.body else None
        return Request(client=client, scheme=stream.scheme if stream.scheme in ("http", "https") else "https", secure=secure, protocol="HTTP/2.0", method=stream.method, target=stream.target, headers=stream.headers, body=body, h2=H2Info(connection_id=self.connection_id, stream_id=stream_id), h3=None, tls=tls)

    def send(self, stream_id: int, response: Response) -> tuple[bytes, os.PathLike | None]:
        headers: list[tuple[str, str]] = [(":status", str(response.status_code))]
        for name, value in response.headers.items():
            lname = name.lower()
            if lname in ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection"):
                continue
            headers.append((lname, value))

        if response.has_real_body:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            body: bytes = response.body
            max_frame = self.connection.max_outbound_frame_size
            if max_frame <= 0:
                max_frame = 16384
            for offset in range(0, len(body), max_frame):
                chunk = body[offset:offset + max_frame]
                self.connection.send_data(stream_id, chunk, end_stream=(offset + len(chunk) >= len(body)))
            if not body:
                self.connection.end_stream(stream_id)
            return self.connection.data_to_send(), None

        elif response.body is not None:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            return self.connection.data_to_send(), response.body

        else:
            self.connection.send_headers(stream_id, headers, end_stream=True)
            return self.connection.data_to_send(), None

    def send_headers(self, stream_id: int, response: Response) -> bytes:
        headers: list[tuple[str, str]] = [(":status", str(response.status_code))]

        for name, value in response.headers.items():
            lname = name.lower()
            if lname in ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection"):
                continue
            headers.append((lname, value))

        self.connection.send_headers(stream_id, headers, end_stream=False)
        return self.connection.data_to_send()

    def send_chunk(self, stream_id: int, chunk: bytes, end_stream: bool) -> bytes:
        if chunk:
            max_frame = self.connection.max_outbound_frame_size
            if max_frame <= 0:
                max_frame = 16384
            for offset in range(0, len(chunk), max_frame):
                piece = chunk[offset:offset + max_frame]
                self.connection.send_data(stream_id, piece, end_stream=end_stream and (offset + len(piece) >= len(chunk)))
        elif end_stream:
            self.connection.end_stream(stream_id)
        return self.connection.data_to_send()

    def ws_accept(self, stream_id: int) -> bytes:
        self.connection.send_headers(stream_id, [(":status", "200")], end_stream=False)
        return self.connection.data_to_send()

    def ws_send(self, stream_id: int, data: bytes) -> bytes:
        max_frame = self.connection.max_outbound_frame_size
        if max_frame <= 0:
            max_frame = 16384
        for offset in range(0, len(data), max_frame):
            piece = data[offset:offset + max_frame]
            self.connection.send_data(stream_id, piece, end_stream=False)
        return self.connection.data_to_send()

    def ws_close(self, stream_id: int) -> bytes:
        self.ws_streams.pop(stream_id, None)
        try:
            self.connection.end_stream(stream_id)
        except Exception:
            pass
        return self.connection.data_to_send()

    def close(self, error_code: int = 0) -> bytes:
        self.connection.close_connection(error_code=error_code)
        return self.connection.data_to_send()
