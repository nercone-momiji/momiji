from __future__ import annotations

import os
import ipaddress
from http import HTTPStatus
from typing import Literal

from .models import Request, Response, Headers
from ..tls import TLSInfo

class H1:
    @staticmethod
    def parse(data: bytes, *, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], scheme: Literal["http", "https"] = "http", secure: bool = False, tls: TLSInfo | None = None) -> Request:
        head, sep, rest = data.partition(b"\r\n\r\n")
        if not sep:
            raise ValueError("incomplete HTTP/1.1 request: missing header terminator")

        lines = head.split(b"\r\n")
        if not lines or not lines[0]:
            raise ValueError("empty HTTP/1.1 request line")

        try:
            method_b, target_b, version_b = lines[0].split(b" ", 2)
        except ValueError:
            raise ValueError("malformed HTTP/1.1 request line")

        if version_b != b"HTTP/1.1":
            raise ValueError(f"unsupported HTTP version: {version_b!r}")

        headers = Headers({})
        for line in lines[1:]:
            if not line:
                continue
            name_b, sep_b, value_b = line.partition(b":")
            if not sep_b:
                raise ValueError(f"malformed HTTP/1.1 header: {line!r}")
            headers.append(name_b.decode("latin-1").strip(), value_b.decode("latin-1").strip())

        body: bytes | None = None
        transfer_encoding = (headers.get("Transfer-Encoding") or "").lower()
        content_length = headers.get("Content-Length")

        if "chunked" in transfer_encoding:
            body = H1.decode_chunked(rest)

        elif content_length is not None:
            try:
                n = int(content_length)
            except ValueError:
                raise ValueError(f"invalid Content-Length: {content_length!r}")
            if n < 0:
                raise ValueError(f"negative Content-Length: {n}")
            body = rest[:n] if n > 0 else None

        return Request(client=client, scheme=scheme, secure=secure, protocol="HTTP/1.1", method=method_b.decode("ascii"), target=target_b.decode("latin-1"), headers=headers, body=body, h2=None, h3=None, tls=tls)

    @staticmethod
    def scan_chunked(data: bytes) -> tuple[bytes | None, int] | None:
        body = bytearray()
        i = 0
        while True:
            end = data.find(b"\r\n", i)
            if end == -1:
                return None
            size_line = data[i:end].split(b";", 1)[0].strip()
            try:
                size = int(size_line, 16)
            except ValueError:
                raise ValueError(f"invalid chunk size: {size_line!r}")
            i = end + 2
            if size == 0:
                while True:
                    line_end = data.find(b"\r\n", i)
                    if line_end == -1:
                        return None
                    is_empty = (line_end == i)
                    i = line_end + 2
                    if is_empty:
                        break
                return bytes(body) if body else None, i
            if len(data) < i + size + 2:
                return None
            body.extend(data[i:i + size])
            i += size + 2

    @staticmethod
    def decode_chunked(data: bytes) -> bytes | None:
        result = H1.scan_chunked(data)
        if result is None:
            raise ValueError("malformed chunked body: incomplete")
        body, _ = result
        return body

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
