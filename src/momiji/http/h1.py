import os
from http import HTTPStatus

from .models import Request, Response

class H1:
    @staticmethod
    def parse(request: bytes) -> Request:
        ...

    @staticmethod
    def build(response: Response) -> bytes | tuple[bytes, os.PathLike | None]:
        try:
            phrase = HTTPStatus(response.status_code).phrase
        except ValueError:
            phrase = ""

        built = f"HTTP/1.1 {response.status_code}" + (f" {phrase}" if phrase else "") + "\r\n"
        for key, value in response.headers.items():
            built += f"{key}: {value}\r\n"
        built += "\r\n"

        if response.has_real_body:
            return built.encode("latin-1") + response.body
        else:
            return built.encode("latin-1"), response.body
