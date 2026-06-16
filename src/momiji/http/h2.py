from __future__ import annotations

import os
import asyncio
import ipaddress
from typing import Literal
from dataclasses import dataclass, field

import h2.config
import h2.connection
import h2.errors
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
    def __init__(self, connection_id: bytes = b"", max_body_size: int = 16 * 1024 * 1024, max_concurrent_streams: int = 100, max_stream_resets: int = 1000):
        self.connection_id = connection_id
        self.connection = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8"))
        self.streams: dict[int, Stream] = {}
        self.ws_streams: dict[int, asyncio.Queue[bytes | None]] = {}
        self.max_body_size = max_body_size
        self.max_concurrent_streams = max_concurrent_streams
        self.max_stream_resets = max_stream_resets
        self.reset_count = 0
        self.send_buffers: dict[int, bytearray] = {}
        self.send_ended: dict[int, bool] = {}
        self.flow_control_event = asyncio.Event()

    def initiate(self) -> bytes:
        self.connection.initiate_connection()
        self.connection.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1, SettingCodes.MAX_CONCURRENT_STREAMS: self.max_concurrent_streams})
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
                    if stream is not None and len(stream.body) > self.max_body_size:
                        self.streams.pop(event.stream_id, None)
                        try:
                            self.connection.reset_stream(event.stream_id, error_code=h2.errors.ErrorCodes.ENHANCE_YOUR_CALM)
                        except Exception:
                            pass
                    elif event.stream_ended and event.stream_id in self.streams:
                        completed.append(self.finalize(event.stream_id, client, secure, tls))

            elif isinstance(event, h2.events.StreamEnded):
                if event.stream_id in self.ws_streams:
                    self.ws_streams[event.stream_id].put_nowait(None)
                    del self.ws_streams[event.stream_id]
                elif event.stream_id in self.streams:
                    completed.append(self.finalize(event.stream_id, client, secure, tls))

            elif isinstance(event, h2.events.StreamReset):
                self.reset_count += 1
                if self.reset_count > self.max_stream_resets:
                    closed = True
                if event.stream_id in self.ws_streams:
                    self.ws_streams[event.stream_id].put_nowait(None)
                    del self.ws_streams[event.stream_id]
                else:
                    self.streams.pop(event.stream_id, None)
                self.discard_send(event.stream_id)

            elif isinstance(event, h2.events.WindowUpdated):
                if event.stream_id == 0:
                    for sid in list(self.send_buffers.keys()):
                        self.pump(sid)
                else:
                    self.pump(event.stream_id)

            elif isinstance(event, h2.events.ConnectionTerminated):
                for queue in self.ws_streams.values():
                    queue.put_nowait(None)
                self.ws_streams.clear()
                self.streams.clear()
                self.send_buffers.clear()
                self.send_ended.clear()
                closed = True

        for sid in list(self.send_buffers.keys()):
            self.pump(sid)

        self.flow_control_event.set()

        return self.connection.data_to_send(), completed, ws_upgrades, closed

    def enqueue(self, stream_id: int, data: bytes, end_stream: bool) -> None:
        buf = self.send_buffers.get(stream_id)
        if buf is None:
            buf = bytearray()
            self.send_buffers[stream_id] = buf
        buf.extend(data)
        if end_stream:
            self.send_ended[stream_id] = True

    def discard_send(self, stream_id: int) -> None:
        self.send_buffers.pop(stream_id, None)
        self.send_ended.pop(stream_id, None)

    def pump(self, stream_id: int) -> None:
        buf = self.send_buffers.get(stream_id)
        ended = self.send_ended.get(stream_id, False)

        if buf is None:
            if ended:
                try:
                    self.connection.end_stream(stream_id)
                except Exception:
                    pass
                self.send_ended.pop(stream_id, None)
            return

        try:
            while buf:
                window = self.connection.local_flow_control_window(stream_id)
                if window <= 0:
                    return
                max_frame = self.connection.max_outbound_frame_size or 16384
                size = min(len(buf), window, max_frame)
                chunk = bytes(buf[:size])
                del buf[:size]
                end = ended and not buf
                self.connection.send_data(stream_id, chunk, end_stream=end)
                if end:
                    self.discard_send(stream_id)
                    return

            if ended:
                self.connection.end_stream(stream_id)
                self.discard_send(stream_id)

        except Exception:
            self.discard_send(stream_id)

    def stream_buffered(self, stream_id: int) -> int:
        buf = self.send_buffers.get(stream_id)
        return len(buf) if buf else 0

    def build_headers(self, response: Response) -> list[tuple[str, str]]:
        headers: list[tuple[str, str]] = [(":status", str(response.status_code))]
        for name, value in response.headers.items():
            lname = name.lower()
            if lname in ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection"):
                continue
            if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue
            headers.append((lname, value))
        return headers

    def finalize(self, stream_id: int, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], secure: bool, tls: TLSInfo | None) -> Request:
        stream = self.streams.pop(stream_id)
        body = bytes(stream.body) if stream.body else None
        return Request(client=client, scheme=stream.scheme if stream.scheme in ("http", "https") else "https", secure=secure, protocol="HTTP/2.0", method=stream.method, target=stream.target, headers=stream.headers, body=body, h2=H2Info(connection_id=self.connection_id, stream_id=stream_id), h3=None, tls=tls)

    def send(self, stream_id: int, response: Response) -> tuple[bytes, os.PathLike | None]:
        headers = self.build_headers(response)

        if response.has_real_body:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            self.enqueue(stream_id, response.body, end_stream=True)
            self.pump(stream_id)
            return self.connection.data_to_send(), None

        elif response.body is not None:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            return self.connection.data_to_send(), response.body

        else:
            self.connection.send_headers(stream_id, headers, end_stream=True)
            return self.connection.data_to_send(), None

    def send_headers(self, stream_id: int, response: Response) -> bytes:
        self.connection.send_headers(stream_id, self.build_headers(response), end_stream=False)
        return self.connection.data_to_send()

    def send_chunk(self, stream_id: int, chunk: bytes, end_stream: bool) -> bytes:
        self.enqueue(stream_id, chunk, end_stream)
        self.pump(stream_id)
        return self.connection.data_to_send()

    def ws_accept(self, stream_id: int, subprotocol: str | None = None, extensions: str | None = None) -> bytes:
        headers = [(":status", "200")]
        if subprotocol:
            headers.append(("sec-websocket-protocol", subprotocol))
        if extensions:
            headers.append(("sec-websocket-extensions", extensions))
        self.connection.send_headers(stream_id, headers, end_stream=False)
        return self.connection.data_to_send()

    def ws_send(self, stream_id: int, data: bytes) -> bytes:
        self.enqueue(stream_id, data, end_stream=False)
        self.pump(stream_id)
        return self.connection.data_to_send()

    def ws_close(self, stream_id: int) -> bytes:
        self.ws_streams.pop(stream_id, None)
        self.send_ended[stream_id] = True
        self.pump(stream_id)
        return self.connection.data_to_send()

    def close(self, error_code: int = 0) -> bytes:
        self.connection.close_connection(error_code=error_code)
        return self.connection.data_to_send()
