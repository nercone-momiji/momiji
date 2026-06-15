from __future__ import annotations

import os
import socket
from typing import Literal

from .app import App
from .config import Config
from .http import Listener

class Server:
    def __init__(self, app: App, config: Config | None = None):
        self.app = app
        self.config = config or Config()

    def bind_socket(self, host: str, port: int, type: Literal["http", "https", "quic", "unix"]) -> socket.socket:
        ...

    def bind_unix(self, path: os.PathLike) -> socket.socket:
        if os.path.exists(path):
            os.unlink(path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(os.fspath(path))
        sock.listen(socket.SOMAXCONN)
        sock.setblocking(False)
        return sock

    def parse_host_port(self, value: str) -> tuple[str, int]:
        host, _, port = value.rpartition(":")
        return host.strip("[]"), int(port)

    @property
    def listeners(self) -> list[Listener]:
        listeners: list[Listener] = []

        for value in self.config.bind_http:
            host, port = self.parse_host_port(value)
            listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_STREAM), "http"))

        for value in self.config.bind_https:
            host, port = self.parse_host_port(value)
            listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_STREAM), "https"))

        for value in self.config.bind_quic:
            host, port = self.parse_host_port(value)
            listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_DGRAM), "quic"))

        for path in self.config.bind_unix:
            listeners.append(Listener(self.bind_unix(path), "unix"))

        return listeners

    def run(self):
        ...

    async def serve(self):
        ...
