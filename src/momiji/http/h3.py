from __future__ import annotations

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
class Stream:
    method: str = ""
    target: str = ""
    scheme: str = "https"
    authority: str = ""
    headers: Headers = field(default_factory=lambda: Headers({}))
    body: bytearray = field(default_factory=bytearray)

class H3:
    def __init__(self, quic: QuicConnection, connection_id: bytes = b""):
        self.connection_id = connection_id
        self.quic = quic
        self.connection = H3Connection(quic)
        self.streams: dict[int, Stream] = {}

    def receive(self, *, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], scheme: Literal["http", "https"] = "https", secure: bool = True, tls: TLSInfo | None = None) -> list[Request]:
        completed: list[Request] = []
        while True:
            quic_event = self.quic.next_event()
            if quic_event is None:
                break
            completed.extend(self.handle_event(quic_event, client=client, scheme=scheme, secure=secure, tls=tls))
        return completed

    def handle_event(self, quic_event, *, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], scheme: Literal["http", "https"] = "https", secure: bool = True, tls: TLSInfo | None = None) -> list[Request]:
        completed: list[Request] = []
        for event in self.connection.handle_event(quic_event):
            if isinstance(event, HeadersReceived):
                stream = Stream(scheme=scheme)
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
                    elif not nb.startswith(":"):
                        stream.headers.append(nb, vb)
                self.streams[event.stream_id] = stream
                if event.stream_ended:
                    completed.append(self.finalize(event.stream_id, client, secure, tls))

            elif isinstance(event, DataReceived):
                stream = self.streams.get(event.stream_id)
                if stream is not None:
                    stream.body.extend(event.data)
                if event.stream_ended and event.stream_id in self.streams:
                    completed.append(self.finalize(event.stream_id, client, secure, tls))

        return completed

    def finalize(self, stream_id: int, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], secure: bool, tls: TLSInfo | None) -> Request:
        stream = self.streams.pop(stream_id)
        body = bytes(stream.body) if stream.body else None
        return Request(client=client, scheme=stream.scheme if stream.scheme in ("http", "https") else "https", secure=secure, protocol="HTTP/3.0", method=stream.method, target=stream.target, headers=stream.headers, body=body, h2=None, h3=H3Info(connection_id=self.connection_id, stream_id=stream_id), tls=tls)

    def send(self, stream_id: int, response: Response) -> None:
        headers: list[tuple[bytes, bytes]] = [(b":status", str(response.status_code).encode("ascii"))]
        for name, value in response.headers.items():
            lname = name.lower()
            if lname in ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection"):
                continue
            headers.append((lname.encode("ascii"), value.encode("utf-8")))

        if response.has_real_body:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            self.connection.send_data(stream_id, response.body, end_stream=True)
        else:
            self.connection.send_headers(stream_id, headers, end_stream=True)
