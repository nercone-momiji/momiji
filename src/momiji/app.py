from typing import Awaitable
from .http import Request, Response, WebSocket

class App:
    websocket_subprotocols: list[str] = []

    def __init__(self):
        pass

    async def on_start(self):
        pass

    async def on_stop(self):
        pass

    async def on_request(self, request: Request) -> Response | Awaitable[Response]:
        return Response("Hello, World! This is the Response from the default Momiji Application.".encode(), content_type="text/plain")

    async def on_websocket(self, request: Request, ws: WebSocket):
        await ws.close(1008, "WebSocket not configured")

class Middleware:
    def __init__(self):
        pass

    async def on_start(self):
        pass

    async def on_stop(self):
        pass

    async def on_request(self, request: Request) -> Request | Response | None:
        pass

    async def on_websocket(self, request: Request, ws: WebSocket) -> tuple[Request, WebSocket] | None:
        pass
