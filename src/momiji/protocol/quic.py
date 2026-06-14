import asyncio
import ipaddress
from typing import TYPE_CHECKING
from dataclasses import dataclass

from qh3.asyncio import serve as quic_serve
from qh3.asyncio.protocol import QuicConnectionProtocol
from qh3.h3.connection import H3Connection, H3_ALPN
from qh3.h3.events import DataReceived as H3DataReceived, HeadersReceived
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.events import ProtocolNegotiated, StreamDataReceived, StreamReset

from .http import Request, process, parse_pseudo_headers

if TYPE_CHECKING:
    from ..app import App
    from ..config import Config

@dataclass
class QUICInfo:
    connection_id: bytes
    stream_id: int

class HTTP3Protocol(QuicConnectionProtocol):
    app: "App" = None
    config: "Config" = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http: H3Connection | None = None
        self.streams: dict[int, dict] = {}
        self.rejected: set[int] = set()
        self.tasks: set[asyncio.Task] = set()
        self.client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.IPv4Address('127.0.0.1')
        self.client_port: int = 0
        self.cid: bytes = b''
        self.conn_info_cached: bool = False

    def cache_connection_info(self):
        if self.conn_info_cached:
            return
        self.conn_info_cached = True
        try:
            self.cid = bytes(self._quic.host_cid)
        except Exception:
            pass
        try:
            network_paths = self._quic._network_paths
            addr = network_paths[0].addr if network_paths else None
            if addr is not None:
                self.client_ip = ipaddress.ip_address(str(addr[0]).split('%')[0])
                self.client_port = int(addr[1])
        except Exception:
            pass

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol in H3_ALPN:
                self.http = H3Connection(self._quic)

        elif self.http is not None and isinstance(event, (StreamDataReceived, StreamReset)):
            for h3_event in self.http.handle_event(event):
                if isinstance(h3_event, HeadersReceived):
                    method, path, headers = parse_pseudo_headers(h3_event.headers)
                    content_length = headers.get("content-length")
                    if content_length is not None:
                        try:
                            if int(content_length) > self.config.request_max_body_size:
                                self.rejected.add(h3_event.stream_id)
                                self.send_simple_response(h3_event.stream_id, 413, b"Payload Too Large")
                                continue
                        except ValueError:
                            pass
                    self.streams[h3_event.stream_id] = {
                        'method': method,
                        'path': path,
                        'headers': headers,
                        'body': bytearray(),
                        'body_size': 0
                    }
                    if h3_event.stream_ended:
                        self.dispatch(h3_event.stream_id)

                elif isinstance(h3_event, H3DataReceived):
                    if h3_event.stream_id in self.rejected:
                        continue

                    if h3_event.stream_id in self.streams:
                        stream = self.streams[h3_event.stream_id]
                        stream['body_size'] += len(h3_event.data)
                        if stream['body_size'] > self.config.request_max_body_size:
                            self.streams.pop(h3_event.stream_id)
                            self.rejected.add(h3_event.stream_id)
                            self.send_simple_response(h3_event.stream_id, 413, b"Payload Too Large")
                            continue
                        stream['body'] += h3_event.data

                    if h3_event.stream_ended and h3_event.stream_id in self.streams:
                        self.dispatch(h3_event.stream_id)

    def send_simple_response(self, stream_id: int, status_code: int, body: bytes):
        try:
            self.http.send_headers(stream_id=stream_id, headers=[(b':status', str(status_code).encode())])
            self.http.send_data(stream_id=stream_id, data=body, end_stream=True)
            self.transmit()
        except Exception:
            pass

    def connection_lost(self, exc):
        for t in self.tasks:
            t.cancel()
        super().connection_lost(exc)

    def dispatch(self, stream_id: int):
        t = asyncio.create_task(self.handle_request(stream_id))
        self.tasks.add(t)
        t.add_done_callback(self.tasks.discard)

    async def handle_request(self, stream_id: int):
        if stream_id not in self.streams:
            return
        stream = self.streams.pop(stream_id)

        self.cache_connection_info()

        request = Request(
            client=(self.client_ip, self.client_port),
            scheme='https',
            secure=True,
            protocol='HTTP/3.0',
            method=stream['method'],
            target=stream['path'],
            headers=stream['headers'],
            body=bytes(stream['body']) if stream['body'] else None,
            tls=None,
            quic=QUICInfo(connection_id=self.cid, stream_id=stream_id)
        )
        response = await process(self.app, request)

        resp_headers = [(b':status', str(response.status_code).encode()), *((k.encode(), v.encode()) for k, v in list(response.headers.items()))]

        self.http.send_headers(stream_id=stream_id, headers=resp_headers)
        self.http.send_data(stream_id=stream_id, data=response.body, end_stream=True)
        self.transmit()

class QUICServer:
    def __init__(self, app: "App", config: "Config", host: str, port: int):
        self.app = app
        self.config = config
        self.host = host
        self.port = port

    async def run(self):
        quic_config = QuicConfiguration(is_client=False, alpn=H3_ALPN)
        quic_config.load_cert_chain(self.config.certfile, self.config.keyfile)

        def make_protocol(*args, **kwargs):
            proto = HTTP3Protocol(*args, **kwargs)
            proto.app = self.app
            proto.config = self.config
            return proto

        async with quic_serve(self.host, self.port, configuration=quic_config, create_protocol=make_protocol):
            await asyncio.Future()
