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
    def __init__(self, app: App, middlewares: list[Middleware], config: Config | None = None):
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

    def listeners(self) -> list[Listener]:
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

        if h3_enabled:
            for value in self.config.bind_quic:
                host, port = self.parse_host_port(value)
                listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_DGRAM), "quic"))

        return listeners

    def run(self):
        workers = self.config.workers if self.config.workers > 0 else (os.cpu_count() or 1)
        listeners = self.listeners()

        if workers == 1:
            uvloop.run(self.serve(listeners))
            return

        if not hasattr(os, "fork"):
            raise RuntimeError("multiprocessing requires a Unix platform (os.fork not available)")

        pids: list[int] = []
        alive: set[int] = set()

        try:
            for i in range(workers):
                pid = os.fork()
                if pid == 0:
                    try:
                        uvloop.run(self.serve(listeners))
                    except KeyboardInterrupt:
                        pass
                    finally:
                        os._exit(0)
                pids.append(pid)
                alive.add(pid)

            def forward_signal(signum, frame):
                for pid in list(alive):
                    try:
                        os.kill(pid, signum)
                    except ProcessLookupError:
                        pass

            signal.signal(signal.SIGINT, forward_signal)
            signal.signal(signal.SIGTERM, forward_signal)

            while alive:
                try:
                    pid, _ = os.wait()
                    alive.discard(pid)
                except ChildProcessError:
                    break

        finally:
            for pid in alive:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

    async def serve(self, listeners: list[Listener] | None = None):
        handlers = [Handler(listener, self.app, self.config) for listener in (listeners if listeners is not None else self.listeners())]

        for handler in handlers:
            await handler.start()

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

            await self.app.on_stop()

            for handler in handlers:
                await handler.stop()
