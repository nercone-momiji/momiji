import os
from typing import Literal
from .config import Config

class Request:
    method: Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
    target: str
    protocol: Literal["HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]
    headers: dict[str,str]
    body: bytes | None

class Response:
    protocol: Literal["HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"] | None = None
    status_code: int = 200
    status_text: str | None = None
    headers: dict[str,str]
    body: bytes | os.PathLike | None

class App:
    def __init__(self, config: Config):
        pass

    def __call__(self, request: Request) -> Response:
        pass
