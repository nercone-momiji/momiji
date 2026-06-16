from __future__ import annotations

import os
import ipaddress
from http import HTTPStatus
from typing import Literal

from .models import Request, Response, Headers
from ..tls import TLSInfo

class H1:
    @staticmethod
    def parse(data: bytes, *, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], scheme: Literal["http", "https"] = "http", secure: bool = False, tls: TLSInfo | None = None, max_body_size: int | None = None) -> Request:
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

        if transfer_encoding:
            te_tokens = [t.strip() for t in transfer_encoding.split(",") if t.strip()]
            if te_tokens[-1:] != ["chunked"] or te_tokens.count("chunked") != 1:
                raise ValueError(f"invalid Transfer-Encoding: {transfer_encoding!r}")
            is_chunked = True
        else:
            is_chunked = False

        if is_chunked and content_length is not None:
            raise ValueError("both Transfer-Encoding and Content-Length present")

        if is_chunked:
            body = H1.decode_chunked(rest, max_body_size=max_body_size)

        elif content_length is not None:
            if not (content_length.isascii() and content_length.isdigit()):
                raise ValueError(f"invalid Content-Length: {content_length!r}")
            n = int(content_length)
            if max_body_size is not None and n > max_body_size:
                raise ValueError(f"Content-Length exceeds max_body_size: {n}")
            body = rest[:n] if n > 0 else None

        return Request(client=client, scheme=scheme, secure=secure, protocol="HTTP/1.1", method=method_b.decode("ascii"), target=target_b.decode("latin-1"), headers=headers, body=body, h2=None, h3=None, tls=tls)

    @staticmethod
    def scan_chunked(data: bytes, max_body_size: int | None = None) -> tuple[bytes | None, int] | None:
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

            if size < 0:
                raise ValueError(f"negative chunk size: {size}")

            if max_body_size is not None and len(body) + size > max_body_size:
                raise ValueError("chunked body exceeds max_body_size")

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

            if data[i + size:i + size + 2] != b"\r\n":
                raise ValueError("malformed chunk: missing CRLF terminator")

            body.extend(data[i:i + size])
            i += size + 2

    @staticmethod
    def decode_chunked(data: bytes, max_body_size: int | None = None) -> bytes | None:
        result = H1.scan_chunked(data, max_body_size=max_body_size)
        if result is None:
            raise ValueError("malformed chunked body: incomplete")
        body, _ = result
        return body

    @staticmethod
    def build_head(response: Response) -> bytes:
        try:
            phrase = HTTPStatus(response.status_code).phrase
        except ValueError:
            phrase = ""
        built = f"HTTP/1.1 {response.status_code}" + (f" {phrase}" if phrase else "") + "\r\n"
        for key, value in response.headers.items():
            if any(c in key for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue
            built += f"{key}: {value}\r\n"
        built += "\r\n"
        return built.encode("latin-1")

    @staticmethod
    def build(response: Response) -> bytes | tuple[bytes, os.PathLike | None]:
        if response.has_real_body:
            return H1.build_head(response) + response.body
        else:
            return H1.build_head(response), response.body
