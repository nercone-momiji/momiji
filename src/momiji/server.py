from __future__ import annotations

import os
import signal
import socket
import asyncio

from .app import App
from .config import Config
from .http import Listener, Handler

class Server:
    def __init__(self, app: App, config: Config | None = None):
        self.app = app
        self.config = config or Config()

    def bind_unix(self, path: os.PathLike) -> socket.socket:
        if os.path.exists(path):
            os.unlink(path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(os.fspath(path))
        sock.listen(socket.SOMAXCONN)
        sock.setblocking(False)
        return sock

    def bind_socket(self, host: str, port: int, type: socket.SocketKind) -> socket.socket:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, type)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port))
        if type == socket.SOCK_STREAM:
            sock.listen(socket.SOMAXCONN)
        sock.setblocking(False)
        return sock

    def parse_host_port(self, value: str) -> tuple[str, int]:
        host, _, port = value.rpartition(":")
        return host.strip("[]"), int(port)

    @property
    def listeners(self) -> list[Listener]:
        listeners: list[Listener] = []

        for path in self.config.bind_unix:
            listeners.append(Listener(self.bind_unix(path), "unix"))

        for value in self.config.bind_http:
            host, port = self.parse_host_port(value)
            listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_STREAM), "http"))

        for value in self.config.bind_https:
            host, port = self.parse_host_port(value)
            listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_STREAM), "https"))

        for value in self.config.bind_quic:
            host, port = self.parse_host_port(value)
            listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_DGRAM), "quic"))

        return listeners

    def run(self):
        asyncio.run(self.serve())

    async def serve(self):
        listeners = self.listeners
        handlers = [Handler(listener, self.app, self.config) for listener in listeners]

        for handler in handlers:
            await handler.start()

        loop = asyncio.get_running_loop()
        stop = loop.create_future()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set_result, None)

        try:
            await stop
        finally:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.remove_signal_handler(sig)
            for handler in handlers:
                await handler.stop()
