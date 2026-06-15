from __future__ import annotations

import asyncio
import base64
import hashlib
import struct
from enum import IntEnum
from typing import Protocol, runtime_checkable

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

def build_frame(opcode: Opcode, payload: bytes, fin: bool = True) -> bytes:
    b1 = (0x80 if fin else 0x00) | (opcode & 0x0F)
    n = len(payload)
    if n < 126:
        header = bytes([b1, n])
    elif n < 65536:
        header = bytes([b1, 126]) + struct.pack(">H", n)
    else:
        header = bytes([b1, 127]) + struct.pack(">Q", n)
    return header + payload

class Frame:
    __slots__ = ("fin", "opcode", "payload", "masked")

    def __init__(self, fin: bool, opcode: Opcode, payload: bytes, masked: bool):
        self.fin = fin
        self.opcode = opcode
        self.payload = payload
        self.masked = masked

def parse_frames(buf: bytearray) -> list[Frame]:
    frames: list[Frame] = []

    while len(buf) >= 2:
        b1, b2 = buf[0], buf[1]
        fin = bool(b1 & 0x80)
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
        frames.append(Frame(fin, opcode, payload, masked))

    return frames

class WebSocket:
    def __init__(self, transport: WriteTransport, *, require_masking: bool = True):
        self.transport = transport
        self.require_masking = require_masking
        self.queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.closed = False
        self.fragments: bytearray = bytearray()
        self.fragment_opcode: Opcode | None = None

    def feed_frame(self, frame: Frame) -> None:
        if self.require_masking and not frame.masked:
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
                self.queue.put_nowait(frame.payload)
            else:
                self.fragments = bytearray(frame.payload)
                self.fragment_opcode = frame.opcode
        elif frame.opcode == Opcode.CONTINUATION:
            self.fragments.extend(frame.payload)
            if frame.fin:
                self.queue.put_nowait(bytes(self.fragments))
                self.fragments = bytearray()
                self.fragment_opcode = None

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
            self.transport.write(build_frame(Opcode.TEXT, data.encode("utf-8")))
        else:
            self.transport.write(build_frame(Opcode.BINARY, data))

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self.closed:
            return
        self.closed = True
        payload = struct.pack(">H", code) + reason.encode("utf-8")
        self.transport.write(build_frame(Opcode.CLOSE, payload))
        self.transport.close()
