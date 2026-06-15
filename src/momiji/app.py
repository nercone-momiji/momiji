from typing import Awaitable
from .http import Request, Response, WebSocket

class App:
    def __init__(self):
        pass

    def __call__(self, request: Request) -> Response | Awaitable[Response]:
        return Response("Hello, World! This is the Response from the default Momiji Application.".encode(), content_type="text/plain")

    async def on_start(self):
        pass

    async def on_stop(self):
        pass

    async def on_websocket(self, request: Request, ws: WebSocket):
        await ws.close(1008, "WebSocket not configured")

class Middleware:
    def __init__(self):
        pass

    def __call__(self, request: Request) -> Request | Response | None:
        return Response("Hello, World! This is an Interrupt Response from the default Momiji Middleware.".encode(), content_type="text/plain")

    async def on_start(self):
        pass

    async def on_stop(self):
        pass

    async def on_websocket(self, request: Request, ws: WebSocket) -> tuple[Request, WebSocket] | None:
        await ws.close(1008, "WebSocket not configured")
