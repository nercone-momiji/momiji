from __future__ import annotations

import zlib
import asyncio
import base64
import hashlib
import struct
from enum import IntEnum
from typing import Any, Protocol, runtime_checkable

@runtime_checkable
class WriteTransport(Protocol):
    def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...

class Opcode(IntEnum):
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA

def compute_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()

def build_frame(opcode: Opcode, payload: bytes, fin: bool = True, rsv1: bool = False) -> bytes:
    b1 = (0x80 if fin else 0x00) | (0x40 if rsv1 else 0x00) | (opcode & 0x0F)
    n = len(payload)
    if n < 126:
        header = bytes([b1, n])
    elif n < 65536:
        header = bytes([b1, 126]) + struct.pack(">H", n)
    else:
        header = bytes([b1, 127]) + struct.pack(">Q", n)
    return header + payload

class Frame:
    __slots__ = ("fin", "rsv1", "rsv_other", "opcode", "payload", "masked")

    def __init__(self, fin: bool, rsv1: bool, rsv_other: bool, opcode: Opcode, payload: bytes, masked: bool):
        self.fin = fin
        self.rsv1 = rsv1
        self.rsv_other = rsv_other
        self.opcode = opcode
        self.payload = payload
        self.masked = masked

def parse_frames(buf: bytearray) -> list[Frame]:
    frames: list[Frame] = []

    while len(buf) >= 2:
        b1, b2 = buf[0], buf[1]
        fin = bool(b1 & 0x80)
        rsv1 = bool(b1 & 0x40)
        rsv_other = bool(b1 & 0x30)
        opcode = Opcode(b1 & 0x0F)
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F
        offset = 2

        if length == 126:
            if len(buf) < 4:
                break
            length = struct.unpack_from(">H", buf, 2)[0]
            offset = 4
        elif length == 127:
            if len(buf) < 10:
                break
            length = struct.unpack_from(">Q", buf, 2)[0]
            offset = 10

        mask_end = offset + (4 if masked else 0)
        if len(buf) < mask_end + length:
            break

        if masked:
            mask_key = bytes(buf[offset:offset + 4])
            raw = bytearray(buf[mask_end:mask_end + length])
            for i in range(length):
                raw[i] ^= mask_key[i % 4]
            payload = bytes(raw)
        else:
            payload = bytes(buf[mask_end:mask_end + length])

        del buf[:mask_end + length]
        frames.append(Frame(fin, rsv1, rsv_other, opcode, payload, masked))

    return frames

class PerMessageDeflate:
    def __init__(self, server_no_context_takeover: bool = True, client_no_context_takeover: bool = False, server_max_window_bits: int = 15, client_max_window_bits: int = 15):
        self.server_no_context_takeover = server_no_context_takeover
        self.client_no_context_takeover = client_no_context_takeover
        self.server_max_window_bits = server_max_window_bits
        self.client_max_window_bits = client_max_window_bits
        self.compress_ctx: Any | None = None
        self.decompress_ctx: Any | None = None

    def compress(self, data: bytes) -> bytes:
        if self.server_no_context_takeover:
            ctx = zlib.compressobj(wbits=-self.server_max_window_bits)
        else:
            if self.compress_ctx is None:
                self.compress_ctx = zlib.compressobj(wbits=-self.server_max_window_bits)
            ctx = self.compress_ctx
        compressed = ctx.compress(data) + ctx.flush(zlib.Z_SYNC_FLUSH)
        if compressed.endswith(b"\x00\x00\xff\xff"):
            compressed = compressed[:-4]
        return compressed

    def decompress(self, data: bytes) -> bytes:
        data = data + b"\x00\x00\xff\xff"
        if self.client_no_context_takeover:
            ctx = zlib.decompressobj(wbits=-self.client_max_window_bits)
        else:
            if self.decompress_ctx is None:
                self.decompress_ctx = zlib.decompressobj(wbits=-self.client_max_window_bits)
            ctx = self.decompress_ctx
        return ctx.decompress(data)

    def response_header(self) -> str:
        parts = ["permessage-deflate"]
        if self.server_no_context_takeover:
            parts.append("server_no_context_takeover")
        if self.client_no_context_takeover:
            parts.append("client_no_context_takeover")
        if self.server_max_window_bits != 15:
            parts.append(f"server_max_window_bits={self.server_max_window_bits}")
        if self.client_max_window_bits != 15:
            parts.append(f"client_max_window_bits={self.client_max_window_bits}")
        return "; ".join(parts)

    @staticmethod
    def from_client_offer(header: str) -> PerMessageDeflate | None:
        for offer in header.split(","):
            parts = [p.strip() for p in offer.split(";")]
            if not parts or parts[0].lower() != "permessage-deflate":
                continue

            params: dict[str, str | bool] = {}
            for part in parts[1:]:
                if "=" in part:
                    k, _, v = part.partition("=")
                    params[k.strip().lower()] = v.strip()
                else:
                    params[part.strip().lower()] = True

            client_no_ctx = "client_no_context_takeover" in params

            server_max = 15
            v = params.get("server_max_window_bits")
            if v is not None and v is not True:
                try:
                    server_max = max(8, min(15, int(v)))
                except (ValueError, TypeError):
                    pass

            client_max = 15
            v = params.get("client_max_window_bits")
            if v is not None and v is not True:
                try:
                    client_max = max(8, min(15, int(v)))
                except (ValueError, TypeError):
                    pass

            return PerMessageDeflate(server_no_context_takeover=True, client_no_context_takeover=client_no_ctx, server_max_window_bits=server_max, client_max_window_bits=client_max)
        return None

class WebSocket:
    def __init__(self, transport: WriteTransport, *, require_masking: bool = True, subprotocol: str | None = None, deflate: PerMessageDeflate | None = None):
        self.transport = transport
        self.require_masking = require_masking
        self.subprotocol = subprotocol
        self.deflate = deflate
        self.queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.closed = False
        self.fragments: bytearray = bytearray()
        self.fragment_opcode: Opcode | None = None
        self.fragment_rsv1: bool = False

    def decompress(self, payload: bytes, rsv1: bool) -> bytes:
        if rsv1 and self.deflate is not None:
            return self.deflate.decompress(payload)
        return payload

    def feed_frame(self, frame: Frame) -> None:
        if self.require_masking and not frame.masked:
            self.close_transport(1002)
            return

        if frame.rsv_other:
            self.close_transport(1002)
            return

        if frame.rsv1 and self.deflate is None:
            self.close_transport(1002)
            return

        if frame.opcode == Opcode.PING:
            if not self.closed:
                self.transport.write(build_frame(Opcode.PONG, frame.payload))
            return

        if frame.opcode == Opcode.PONG:
            return

        if frame.opcode == Opcode.CLOSE:
            if not self.closed:
                self.closed = True
                echo = frame.payload[:2] if len(frame.payload) >= 2 else b""
                self.transport.write(build_frame(Opcode.CLOSE, echo))
                self.transport.close()
            self.queue.put_nowait(None)
            return

        if frame.opcode in (Opcode.TEXT, Opcode.BINARY):
            if frame.fin:
                self.queue.put_nowait(self.decompress(frame.payload, frame.rsv1))
            else:
                self.fragments = bytearray(frame.payload)
                self.fragment_opcode = frame.opcode
                self.fragment_rsv1 = frame.rsv1

        elif frame.opcode == Opcode.CONTINUATION:
            self.fragments.extend(frame.payload)
            if frame.fin:
                self.queue.put_nowait(self.decompress(bytes(self.fragments), self.fragment_rsv1))
                self.fragments = bytearray()
                self.fragment_opcode = None
                self.fragment_rsv1 = False

    def close_transport(self, code: int) -> None:
        if not self.closed:
            self.closed = True
            self.transport.write(build_frame(Opcode.CLOSE, struct.pack(">H", code)))
            self.transport.close()
        self.queue.put_nowait(None)

    async def ping(self, payload: bytes = b"") -> None:
        if self.closed:
            return
        self.transport.write(build_frame(Opcode.PING, payload))

    async def receive(self) -> bytes | None:
        return await self.queue.get()

    async def send(self, data: bytes | str) -> None:
        if self.closed:
            return

        if isinstance(data, str):
            payload = data.encode("utf-8")
            if self.deflate is not None:
                self.transport.write(build_frame(Opcode.TEXT, self.deflate.compress(payload), rsv1=True))
            else:
                self.transport.write(build_frame(Opcode.TEXT, payload))

        else:
            if self.deflate is not None:
                self.transport.write(build_frame(Opcode.BINARY, self.deflate.compress(data), rsv1=True))
            else:
                self.transport.write(build_frame(Opcode.BINARY, data))

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self.closed:
            return
        self.closed = True
        payload = struct.pack(">H", code) + reason.encode("utf-8")
        self.transport.write(build_frame(Opcode.CLOSE, payload))
        self.transport.close()
