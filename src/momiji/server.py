from __future__ import annotations

import os
import signal
import socket
import uvloop
import asyncio

from .app import App, Middleware
from .config import Config
from .http import Listener, Handler

class Server:
    def __init__(self, app: App, middlewares: list[Middleware] | None = None, config: Config | None = None):
        self.app = app
        self.middlewares = middlewares if middlewares is not None else []
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
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port))
        if type == socket.SOCK_STREAM:
            sock.listen(socket.SOMAXCONN)
        sock.setblocking(False)
        return sock

    def parse_host_port(self, value: str) -> tuple[str, int]:
        host, sep, port = value.rpartition(":")
        if not sep:
            raise ValueError(f"invalid bind address {value!r}: expected 'host:port'")
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        return host, int(port)

    def listeners(self, *, include_quic: bool = True) -> list[Listener]:
        listeners: list[Listener] = []

        h1_enabled = "http/1.1" in self.config.protocols
        h2_enabled = "h2" in self.config.protocols
        h3_enabled = "h3" in self.config.protocols

        if h1_enabled:
            for path in self.config.bind_unix:
                listeners.append(Listener(self.bind_unix(path), "unix"))

            for value in self.config.bind_http:
                host, port = self.parse_host_port(value)
                listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_STREAM), "http"))

        if h1_enabled or h2_enabled:
            for value in self.config.bind_https:
                host, port = self.parse_host_port(value)
                listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_STREAM), "https"))

        if h3_enabled and include_quic:
            listeners.extend(self.quic_listeners())

        return listeners

    def quic_listeners(self) -> list[Listener]:
        listeners: list[Listener] = []
        if "h3" in self.config.protocols:
            for value in self.config.bind_quic:
                host, port = self.parse_host_port(value)
                listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_DGRAM), "quic"))
        return listeners

    def run(self):
        workers = self.config.workers if self.config.workers > 0 else (os.cpu_count() or 1)

        if workers == 1:
            uvloop.run(self.serve(self.listeners()))
            return

        if not hasattr(os, "fork"):
            raise RuntimeError("multiprocessing requires a Unix platform (os.fork not available)")

        alive: set[int] = set()
        shutting_down = False

        shared = self.listeners(include_quic=False)

        def spawn_worker() -> int:
            pid = os.fork()
            if pid == 0:
                try:
                    uvloop.run(self.serve(shared + self.quic_listeners()))
                except KeyboardInterrupt:
                    pass
                finally:
                    os._exit(0)
            alive.add(pid)
            return pid

        for _ in range(workers):
            spawn_worker()

        def forward_signal(signum, frame):
            nonlocal shutting_down
            shutting_down = True
            for pid in list(alive):
                try:
                    os.kill(pid, signum)
                except ProcessLookupError:
                    pass

        signal.signal(signal.SIGINT, forward_signal)
        signal.signal(signal.SIGTERM, forward_signal)

        try:
            while alive:
                try:
                    pid, _ = os.wait()
                    alive.discard(pid)

                    if not shutting_down and self.config.auto_restart:
                        spawn_worker()

                except ChildProcessError:
                    break

        finally:
            for pid in alive:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

    async def serve(self, listeners: list[Listener] | None = None):
        handlers = [Handler(listener, self.app, self.middlewares, self.config) for listener in (listeners if listeners is not None else self.listeners())]

        for handler in handlers:
            await handler.start()

        for middleware in self.middlewares:
            await middleware.on_start()

        await self.app.on_start()

        loop = asyncio.get_running_loop()
        stop = loop.create_future()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set_result, None)

        try:
            await stop
        finally:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.remove_signal_handler(sig)

            await asyncio.gather(*[handler.drain(self.config.shutdown_timeout) for handler in handlers], return_exceptions=True)

            await self.app.on_stop()

            for middleware in reversed(self.middlewares):
                await middleware.on_stop()

            for handler in handlers:
                await handler.stop()
