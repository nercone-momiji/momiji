from __future__ import annotations

from typing import TYPE_CHECKING

from .models import Request, Response
from .optimize import minimize, compress

if TYPE_CHECKING:
    from ..app import App

async def process(app: App, request: Request) -> Response:
    try:
        response = app(request)
        response.protocol = response.protocol or request.protocol
    except Exception:
        response = Response(b"Internal Server Error", status_code=500, compression=False, minification=False, protocol=request.protocol)

    response.headers.set("Server", "Momiji", override=False)

    if response.has_real_body:
        response.body = await minimize(response) or response.body
        response.body = await compress(response, request.headers.get("accept-encoding", "")) or response.body

        response.headers.set("Content-Type", "application/octet-stream", override=False)
        response.headers.set("Content-Length", str(len(response.body)))

    return response
