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

from .http import Request, Response, get_response_body

if TYPE_CHECKING:
    from ..app import App
    from ..config import Config

@dataclass
class QUICInfo:
    connection_id: bytes
    stream_id: int

def decode(value: bytes | str) -> str:
    return value.decode('latin-1') if isinstance(value, bytes) else value

class HTTP3Protocol(QuicConnectionProtocol):
    app = None

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.http: H3Connection | None = None
        self.streams: dict[int, dict] = {}
        self.tasks: set[asyncio.Task] = set()
        self.client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.IPv4Address('127.0.0.1')
        self.client_port: int = 0
        self.cid: bytes = b''
        self.conn_info_cached: bool = False

    def cache_connection_info(self) -> None:
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

    def quic_event_received(self, event) -> None:
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol in H3_ALPN:
                self.http = H3Connection(self._quic)

        elif self.http is not None and isinstance(event, (StreamDataReceived, StreamReset)):
            for h3_event in self.http.handle_event(event):
                if isinstance(h3_event, HeadersReceived):
                    method = 'GET'
                    path = '/'
                    headers: dict[str, str] = {}
                    for raw_k, raw_v in h3_event.headers:
                        k = decode(raw_k)
                        v = decode(raw_v)
                        if k == ':method':
                            method = v
                        elif k == ':path':
                            path = v
                        elif not k.startswith(':'):
                            headers[k] = v
                    self.streams[h3_event.stream_id] = {
                        'method': method,
                        'path': path,
                        'headers': headers,
                        'body': bytearray()
                    }
                    if h3_event.stream_ended:
                        t = asyncio.create_task(self.handle_h3_request(h3_event.stream_id))
                        self.tasks.add(t)
                        t.add_done_callback(self.tasks.discard)

                elif isinstance(h3_event, H3DataReceived):
                    if h3_event.stream_id in self.streams:
                        self.streams[h3_event.stream_id]['body'] += h3_event.data

                    if h3_event.stream_ended and h3_event.stream_id in self.streams:
                        t = asyncio.create_task(self.handle_h3_request(h3_event.stream_id))
                        self.tasks.add(t)
                        t.add_done_callback(self.tasks.discard)

    def connection_lost(self, exc) -> None:
        for t in self.tasks:
            t.cancel()
        super().connection_lost(exc)

    async def handle_h3_request(self, stream_id: int) -> None:
        if stream_id not in self.streams:
            return
        stream_data = self.streams.pop(stream_id)

        self.cache_connection_info()

        try:
            request = Request(
                client=(self.client_ip, self.client_port),
                scheme='https',
                secure=True,
                protocol='HTTP/3.0',
                method=stream_data['method'],
                target=stream_data['path'],
                headers=stream_data['headers'],
                body=bytes(stream_data['body']) if stream_data['body'] else None,
                tls=None,
                quic=QUICInfo(connection_id=self.cid, stream_id=stream_id)
            )
            response = self.app(request)
            body = await get_response_body(response)

        except Exception:
            response = Response("Internal Server Error".encode(), status_code=500)
            body = b"Internal Server Error"

        resp_headers = [(b':status', str(response.status_code).encode()), (b'content-length', str(len(body)).encode()), *((k.encode(), v.encode()) for k, v in response.headers.items())]

        self.http.send_headers(stream_id=stream_id, headers=resp_headers)
        self.http.send_data(stream_id=stream_id, data=body, end_stream=True)
        self.transmit()

class QUICServer:
    def __init__(self, app: "App", config: "Config", host: str, port: int) -> None:
        self.app = app
        self.config = config
        self.host = host
        self.port = port

    async def run(self) -> None:
        quic_config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        quic_config.load_cert_chain(self.config.certfile, self.config.keyfile)

        def make_protocol(*args, **kwargs):
            proto = HTTP3Protocol(*args, **kwargs)
            proto.app = self.app
            return proto

        async with quic_serve(self.host, self.port, configuration=quic_config, create_protocol=make_protocol):
            await asyncio.Future()
