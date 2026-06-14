from __future__ import annotations

import os
import socket
import signal
import asyncio

from .app import App
from .config import Config
from .http import Listener, handle
from .tls import create_ssl_context

class Server:
    def __init__(self, app: type[App] | App, config: Config | None = None):
        if config is None:
            config = Config()
        self.config = config
        self.app = app(config) if isinstance(app, type) else app

    def split_host_port(self, value: str) -> tuple[str, int]:
        host, _, port = value.rpartition(":")
        return host.strip("[]"), int(port)

    def bind_socket(self, host: str, port: int, sock_type: int) -> socket.socket:
        info = socket.getaddrinfo(host, port, type=sock_type)[0]
        family, _, proto, _, address = info
        sock = socket.socket(family, sock_type, proto)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(address)
        if sock_type == socket.SOCK_STREAM:
            sock.listen(socket.SOMAXCONN)
        sock.setblocking(False)
        return sock

    def bind_unix(self, path: os.PathLike) -> socket.socket:
        if os.path.exists(path):
            os.unlink(path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(os.fspath(path))
        sock.listen(socket.SOMAXCONN)
        sock.setblocking(False)
        return sock

    def make_listeners(self) -> list[Listener]:
        listeners: list[Listener] = []
        for value in self.config.bind_http:
            host, port = self.split_host_port(value)
            listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_STREAM), "http"))
        for value in self.config.bind_https:
            host, port = self.split_host_port(value)
            listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_STREAM), "https"))
        for value in self.config.bind_quic:
            host, port = self.split_host_port(value)
            listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_DGRAM), "quic"))
        for path in self.config.bind_unix:
            listeners.append(Listener(self.bind_unix(path), "unix"))
        return listeners

    def make_ssl_context(self):
        if self.config.bind_https and self.config.certfile and self.config.keyfile:
            return create_ssl_context(self.config)
        return None

    def make_quic_config(self):
        if not self.config.bind_quic:
            return None
        from qh3.quic.configuration import QuicConfiguration
        configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        configuration.load_cert_chain(self.config.certfile, self.config.keyfile)
        return configuration

    async def serve(self) -> None:
        await handle(self.app, self.config, self.make_listeners(), self.make_ssl_context(), self.make_quic_config())

    def run_worker(self, listeners, ssl_context, quic_config) -> None:
        try:
            asyncio.run(handle(self.app, self.config, listeners, ssl_context, quic_config))
        except KeyboardInterrupt:
            pass

    def run(self) -> None:
        try:
            import uvloop
            uvloop.install()
        except Exception:
            pass

        listeners = self.make_listeners()
        ssl_context = self.make_ssl_context()
        quic_config = self.make_quic_config()

        workers = self.config.workers or os.cpu_count() or 1
        if workers <= 1:
            self.run_worker(listeners, ssl_context, quic_config)
            return

        children: list[int] = []
        for _ in range(workers):
            pid = os.fork()
            if pid == 0:
                self.run_worker(listeners, ssl_context, quic_config)
                os._exit(0)
            children.append(pid)

        def terminate(*_):
            for pid in children:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

        signal.signal(signal.SIGINT, terminate)
        signal.signal(signal.SIGTERM, terminate)
        for pid in children:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
