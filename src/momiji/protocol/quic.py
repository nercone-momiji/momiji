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

    def quic_event_received(self, event) -> None:
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol in H3_ALPN:
                self.http = H3Connection(self.quic)

        elif self.http is not None and isinstance(event, (StreamDataReceived, StreamReset)):
            for h3_event in self.http.handle_event(event):
                if isinstance(h3_event, HeadersReceived):
                    headers = {decode(k): decode(v) for k, v in h3_event.headers}
                    self.streams[h3_event.stream_id] = {
                        'method': headers.get(':method', 'GET'),
                        'path': headers.get(':path', '/'),
                        'headers': {k: v for k, v in headers.items() if not k.startswith(':')},
                        'body': b''
                    }
                    if h3_event.stream_ended:
                        asyncio.create_task(self.handle_h3_request(h3_event.stream_id))

                elif isinstance(h3_event, H3DataReceived):
                    if h3_event.stream_id in self.streams:
                        self.streams[h3_event.stream_id]['body'] += h3_event.data

                    if h3_event.stream_ended and h3_event.stream_id in self.streams:
                        asyncio.create_task(self.handle_h3_request(h3_event.stream_id))

    async def handle_h3_request(self, stream_id: int) -> None:
        if stream_id not in self.streams:
            return
        stream_data = self.streams.pop(stream_id)

        try:
            network_paths = self.quic.network_paths
            addr = network_paths[0].addr if network_paths else None
        except Exception:
            addr = None

        if addr is None:
            client_ip, client_port = ipaddress.IPv4Address('127.0.0.1'), 0
        else:
            client_ip = ipaddress.ip_address(str(addr[0]).split('%')[0])
            client_port = int(addr[1])

        try:
            cid = bytes(self.quic.host_cid)
        except Exception:
            cid = b''

        try:
            request = Request(
                client=(client_ip, client_port),
                scheme='https',
                secure=True,
                protocol='HTTP/3.0',
                method=stream_data['method'],
                target=stream_data['path'],
                headers=stream_data['headers'],
                body=stream_data['body'] or None,
                tls=None,
                quic=QUICInfo(connection_id=cid, stream_id=stream_id)
            )
            response = self.app(request)
            body = get_response_body(response)

        except Exception:
            response = Response("Internal Server Error".encode(), status_code=500)
            body = "Internal Server Error".encode()

        resp_headers = [(b':status', str(response.status_code).encode()), (b'content-length', str(len(body)).encode())] + [(k.encode() if isinstance(k, str) else k, v.encode() if isinstance(v, str) else v) for k, v in response.headers.items()]

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
