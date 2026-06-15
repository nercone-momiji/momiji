from .http import Request, Response, WebSocket

class App:
    def __init__(self):
        pass

    def __call__(self, request: Request) -> Response:
        return Response("Hello, World! This is Response from Default Momiji Application.".encode(), content_type="text/plain")

    async def on_start(self):
        pass

    async def on_stop(self):
        pass

    async def on_websocket(self, request: Request, ws: WebSocket):
        await ws.close(1008, "WebSocket not configured")
