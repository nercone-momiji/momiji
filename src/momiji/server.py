import os
import signal
import socket
import uvloop
import asyncio

from .app import App
from .config import Config
from .protocol.http import handle_http11, handle_https
from .protocol.tls import create_ssl_context
from .protocol.quic import QUICServer

def parse_host_port(addr: str) -> tuple[str, int]:
    if addr.startswith('['):
        bracket_end = addr.index(']')
        host = addr[1:bracket_end]
        port = int(addr[bracket_end + 2:])
    else:
        host, _, port_str = addr.rpartition(':')
        port = int(port_str)
    return host, port

class Server:
    def __init__(self, app: type[App] | App, config: Config | None = None):
        if config is None:
            config = Config()
        self.config = config
        self.app = app(config) if isinstance(app, type) else app

    def run(self) -> None:
        if self.config.workers <= 0:
            uvloop.run(self.serve())
            return
        self.run_workers()

    def bind_sockets(self) -> list[tuple[str, socket.socket]]:
        bound: list[tuple[str, socket.socket]] = []

        for path in self.config.bind_unix:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                os.unlink(str(path))
            except FileNotFoundError:
                pass
            s.bind(str(path))
            bound.append(('unix', s))

        for addr in self.config.bind_http:
            host, port = parse_host_port(addr)
            af = socket.AF_INET6 if ':' in host else socket.AF_INET
            s = socket.socket(af, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.bind((host, port))
            bound.append(('http', s))

        if self.config.certfile:
            for addr in self.config.bind_https:
                host, port = parse_host_port(addr)
                af = socket.AF_INET6 if ':' in host else socket.AF_INET
                s = socket.socket(af, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, 'SO_REUSEPORT'):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                s.bind((host, port))
                bound.append(('https', s))

        return bound

    def run_workers(self) -> None:
        bound = self.bind_sockets()
        pids: list[int] = []

        for _ in range(self.config.workers):
            pid = os.fork()
            if pid == 0:
                try:
                    uvloop.run(self.serve_prebound(bound))
                finally:
                    os._exit(0)
            pids.append(pid)

        for _, sock in bound:
            sock.close()

        try:
            while pids:
                dead_pid, _ = os.wait()
                if dead_pid in pids:
                    pids.remove(dead_pid)
        except (KeyboardInterrupt, SystemExit):
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            for pid in list(pids):
                try:
                    os.waitpid(pid, 0)
                except Exception:
                    pass

    async def serve_prebound(self, bound: list[tuple[str, socket.socket]]) -> None:
        servers: list[asyncio.Server] = []
        quic_servers: list[QUICServer] = []

        ssl_ctx = None
        if self.config.certfile and self.config.bind_https:
            ssl_ctx = create_ssl_context(self.config)

        for kind, sock in bound:
            if kind == 'unix':
                server = await asyncio.start_unix_server(
                    lambda r, w: handle_http11(r, w, self.app), sock=sock, backlog=1024)
                servers.append(server)

            elif kind == 'http':
                server = await asyncio.start_server(
                    lambda r, w: handle_http11(r, w, self.app), sock=sock, backlog=1024)
                servers.append(server)

            elif kind == 'https':
                server = await asyncio.start_server(
                    lambda r, w: handle_https(r, w, self.app), sock=sock, ssl=ssl_ctx, backlog=1024)
                servers.append(server)

        if self.config.certfile and self.config.bind_quic:
            for addr in self.config.bind_quic:
                host, port = parse_host_port(addr)
                quic_servers.append(QUICServer(self.app, self.config, host, port))

        if not servers and not quic_servers:
            return

        await asyncio.gather(*[s.serve_forever() for s in servers], *[qs.run() for qs in quic_servers])

    async def serve(self) -> None:
        servers: list[asyncio.Server] = []
        quic_servers: list[QUICServer] = []

        for path in self.config.bind_unix:
            server = await asyncio.start_unix_server(lambda r, w: handle_http11(r, w, self.app), path=str(path), backlog=1024)
            servers.append(server)

        for addr in self.config.bind_http:
            host, port = parse_host_port(addr)
            server = await asyncio.start_server(lambda r, w: handle_http11(r, w, self.app), host, port, backlog=1024)
            servers.append(server)

        if self.config.certfile and self.config.bind_https:
            ssl_ctx = create_ssl_context(self.config)
            for addr in self.config.bind_https:
                host, port = parse_host_port(addr)
                server = await asyncio.start_server(lambda r, w: handle_https(r, w, self.app), host, port, ssl=ssl_ctx, backlog=1024)
                servers.append(server)

        if self.config.certfile and self.config.bind_quic:
            for addr in self.config.bind_quic:
                host, port = parse_host_port(addr)
                quic_servers.append(QUICServer(self.app, self.config, host, port))

        if not servers and not quic_servers:
            return

        await asyncio.gather(*[s.serve_forever() for s in servers], *[qs.run() for qs in quic_servers])
