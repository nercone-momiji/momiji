from __future__ import annotations

import os
from .models import Response

_FORBIDDEN_RESPONSE_HEADERS = ("connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection")

def _sanitize_value(value: str) -> str:
    return value.replace("\r", " ").replace("\n", " ").replace("\x00", " ")

def response_fields(response: Response) -> list[tuple[bytes, bytes]]:
    fields: list[tuple[bytes, bytes]] = [(b":status", str(response.status_code).encode())]
    for key, value in response.headers.items():
        lkey = key.lower()
        if lkey in _FORBIDDEN_RESPONSE_HEADERS:
            continue
        safe_value = _sanitize_value(value)
        fields.append((lkey.encode("latin-1"), safe_value.encode("latin-1")))
    return fields

async def build(response: Response, *, encoder=None, stream_id: int | None = None) -> bytes | tuple[bytes, os.PathLike | None]:
    protocol = response.protocol or "HTTP/1.1"
    if protocol == "HTTP/1.1":
        from . import h1
        return h1.serialize_response(response)
    if protocol == "HTTP/2.0":
        from . import h2
        return h2.serialize_response(response, encoder, stream_id, response_fields(response))
    if protocol == "HTTP/3.0":
        from . import h3
        return h3.serialize_response(response, encoder, response_fields(response))
    raise ValueError(f"unsupported protocol {protocol!r}")
