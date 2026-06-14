from __future__ import annotations

import os
import asyncio
import ipaddress
from typing import TYPE_CHECKING, Literal
from dataclasses import dataclass, field

import h11
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ConnectionTerminated, DataReceived, RequestReceived, StreamEnded

from .tls import TLSInfo, extract_tls_info

if TYPE_CHECKING:
    from ..app import App
    from .quic import QUICInfo

@dataclass
class Request:
    client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]
    scheme: Literal["http", "https"]
    secure: bool

    protocol: Literal["HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]
    method: Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
    target: str
    headers: dict[str, str]
    body: bytes | None

    tls: TLSInfo | None
    quic: QUICInfo | None

@dataclass
class Response:
    body: bytes | os.PathLike | None = None
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)

def parse_peername(addr) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    if not addr or len(addr) < 2:
        return ipaddress.IPv4Address('127.0.0.1'), 0
    try:
        return ipaddress.ip_address(str(addr[0]).split('%')[0]), int(addr[1])
    except (ValueError, IndexError):
        return ipaddress.IPv4Address('127.0.0.1'), 0

def get_response_body(response: Response) -> bytes:
    if response.body is None:
        return b''
    if isinstance(response.body, bytes):
        return response.body
    with open(response.body, 'rb') as f:
        return f.read()

async def handle_http11(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, app: App) -> None:
    connection = h11.Connection(our_role=h11.SERVER)
    client_ip, client_port = parse_peername(writer.get_extra_info('peername'))
    ssl_object = writer.get_extra_info('ssl_object')
    secure = ssl_object is not None
    scheme: Literal['http', 'https'] = 'https' if secure else 'http'

    try:
        while True:
            method: str | None = None
            target: str | None = None
            headers: dict[str, str] | None = None
            body_chunks: list[bytes] = []

            while True:
                event = connection.next_event()

                if event is h11.NEED_DATA:
                    try:
                        data = await reader.read(65536)
                    except Exception:
                        return
                    if not data:
                        return
                    connection.receive_data(data)

                elif isinstance(event, h11.Request):
                    method = event.method.decode()
                    target = event.target.decode()
                    headers = {k.decode().lower(): v.decode() for k, v in event.headers}

                elif isinstance(event, h11.Data):
                    body_chunks.append(event.data)

                elif isinstance(event, h11.EndOfMessage):
                    if method is None:
                        return
                    try:
                        request = Request(
                            client=(client_ip, client_port),
                            scheme=scheme,
                            secure=secure,
                            protocol='HTTP/1.1',
                            method=method,
                            target=target or '/',
                            headers=headers or {},
                            body=b''.join(body_chunks) or None,
                            tls=extract_tls_info(ssl_object),
                            quic=None
                        )

                        response = app(request)
                        body = get_response_body(response)

                    except Exception:
                        response = Response("Internal Server Error".encode(), status_code=500)
                        body = "Internal Server Error".encode()

                    writer.write(connection.send(h11.Response(
                        status_code=response.status_code,
                        headers=list(response.headers.items()),
                    )))

                    if body:
                        writer.write(connection.send(h11.Data(data=body)))

                    writer.write(connection.send(h11.EndOfMessage()))
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

async def respond_h2(conn: H2Connection, writer: asyncio.StreamWriter, lock: asyncio.Lock, stream_id: int, stream_data: dict, app, client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, client_port: int, tls: TLSInfo | None = None) -> None:
    try:
        request = Request(
            client=(client_ip, client_port),
            scheme='https',
            secure=True,
            protocol='HTTP/2.0',
            method=stream_data['method'],
            target=stream_data['path'],
            headers=stream_data['headers'],
            body=stream_data['body'] or None,
            tls=tls,
            quic=None
        )
        response = app(request)
        body = get_response_body(response)

    except Exception:
        response = Response("Internal Server Error".encode(), status_code=500)
        body = "Internal Server Error".encode()

    resp_headers = [(':status', str(response.status_code))]
    resp_headers += list(response.headers.items())
    resp_headers.append(('content-length', str(len(body))))

    async with lock:
        conn.send_headers(stream_id=stream_id, headers=resp_headers)
        conn.send_data(stream_id=stream_id, data=body, end_stream=True)
        to_send = conn.data_to_send()
        if to_send:
            writer.write(to_send)
            await writer.drain()

async def handle_http2(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, app: App) -> None:
    client_ip, client_port = parse_peername(writer.get_extra_info('peername'))
    tls_info = extract_tls_info(writer.get_extra_info('ssl_object'))

    config = H2Configuration(client_side=False, header_encoding='utf-8')
    connection = H2Connection(config=config)
    lock = asyncio.Lock()

    async with lock:
        connection.initiate_connection()
        writer.write(connection.data_to_send())
        await writer.drain()

    streams: dict[int, dict] = {}
    tasks: list[asyncio.Task] = []

    try:
        while True:
            try:
                data = await reader.read(65536)
            except Exception:
                return
            if not data:
                break

            pending: list[int] = []

            async with lock:
                events = connection.receive_data(data)
                for event in events:
                    if isinstance(event, RequestReceived):
                        method = 'GET'
                        path = '/'
                        headers: dict[str, str] = {}
                        for k, v in event.headers:
                            if k == ':method':
                                method = v
                            elif k == ':path':
                                path = v
                            elif not k.startswith(':'):
                                headers[k] = v
                        streams[event.stream_id] = {
                            'method': method,
                            'path': path,
                            'headers': headers,
                            'body': b''
                        }
                        if event.stream_ended is not None:
                            pending.append(event.stream_id)

                    elif isinstance(event, DataReceived):
                        connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                        if event.stream_id in streams:
                            streams[event.stream_id]['body'] += event.data

                        if event.stream_ended is not None and event.stream_id in streams:
                            pending.append(event.stream_id)

                    elif isinstance(event, StreamEnded):
                        if event.stream_id in streams:
                            pending.append(event.stream_id)

                    elif isinstance(event, ConnectionTerminated):
                        return

                to_send = connection.data_to_send()
                if to_send:
                    writer.write(to_send)
                    await writer.drain()

            for sid in pending:
                if sid in streams:
                    t = asyncio.create_task(respond_h2(connection, writer, lock, sid, streams.pop(sid), app, client_ip, client_port, tls_info))
                    tasks.append(t)

    except Exception:
        pass

    finally:
        for t in tasks:
            if not t.done():
                t.cancel()

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def handle_https(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, app) -> None:
    ssl_object = writer.get_extra_info('ssl_object')
    if ssl_object is not None and ssl_object.selected_alpn_protocol() == 'h2':
        await handle_http2(reader, writer, app)
    else:
        await handle_http11(reader, writer, app)
