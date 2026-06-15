from __future__ import annotations

import ssl
import asyncio
from typing import TYPE_CHECKING

from . import h1, h2
from .models import Listener, TLSInfo
from ..tls import CIPHER_MAP

if TYPE_CHECKING:
    from ..app import App
    from ..config import Config

def tls_info(ssl_object: ssl.SSLObject | None) -> TLSInfo | None:
    if ssl_object is None:
        return None
    version = ssl_object.version()
    cipher = ssl_object.cipher()
    return TLSInfo(
        version=version if version in ("TLSv1.2", "TLSv1.3", "TLSv1.1", "TLSv1.0", "SSLv3.0") else None,
        group=None,
        cipher=CIPHER_MAP.get(cipher[0]) if cipher else None
    )

def h1_handler(app: App, config: Config, *, scheme: str):
    async def handler(reader, writer):
        await h1.serve_connection(reader, writer, app, config, scheme=scheme, secure=False, tls=None)
    return handler

def tls_handler(app: App, config: Config):
    async def handler(reader, writer):
        ssl_object = writer.get_extra_info("ssl_object")
        alpn = ssl_object.selected_alpn_protocol() if ssl_object else None
        tls = tls_info(ssl_object)
        if alpn == "h2":
            await h2.serve_connection(reader, writer, app, config, scheme="https", secure=True, tls=tls)
        else:
            await h1.serve_connection(reader, writer, app, config, scheme="https", secure=True, tls=tls)
    return handler

async def handle(app: App, config: Config, listeners: list[Listener], ssl_context: ssl.SSLContext | None = None, quic_config=None) -> None:
    loop = asyncio.get_running_loop()
    servers: list = []
    transports: list = []

    for listener in listeners:
        if listener.kind in ("http", "unix"):
            servers.append(await asyncio.start_server(h1_handler(app, config, scheme="http"), sock=listener.sock))

        elif listener.kind == "https":
            if ssl_context is None:
                raise ValueError("https listener requires an ssl_context")
            servers.append(await asyncio.start_server(tls_handler(app, config), sock=listener.sock, ssl=ssl_context))

        elif listener.kind == "quic":
            from . import h3
            from qh3.asyncio.server import QuicServer

            if quic_config is None:
                raise ValueError("quic listener requires a quic_config")

            factory = h3.create_protocol(app, config)
            transport, _ = await loop.create_datagram_endpoint(lambda factory=factory: QuicServer(configuration=quic_config, create_protocol=factory), sock=listener.sock)
            transports.append(transport)

    stop = loop.create_future()

    try:
        await stop

    except asyncio.CancelledError:
        pass

    finally:
        for server in servers:
            server.close()

        for transport in transports:
            transport.close()

        for server in servers:
            try:
                await server.wait_closed()
            except Exception:
                pass
