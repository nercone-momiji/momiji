from __future__ import annotations

import asyncio
from enum import IntEnum
from typing import TYPE_CHECKING

from . import hpack
from .models import Response, TLSInfo
from .parse import parse, ParseError
from .process import process
from .build import build

if TYPE_CHECKING:
    from ..app import App
    from ..config import Config

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

class Frame(IntEnum):
    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    RST_STREAM = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    PING = 0x6
    GOAWAY = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION = 0x9

class Flag(IntEnum):
    END_STREAM = 0x1
    ACK = 0x1
    END_HEADERS = 0x4
    PADDED = 0x8
    PRIORITY = 0x20

class Setting(IntEnum):
    HEADER_TABLE_SIZE = 0x1
    ENABLE_PUSH = 0x2
    MAX_CONCURRENT_STREAMS = 0x3
    INITIAL_WINDOW_SIZE = 0x4
    MAX_FRAME_SIZE = 0x5
    MAX_HEADER_LIST_SIZE = 0x6

class ErrorCode(IntEnum):
    NO_ERROR = 0x0
    PROTOCOL_ERROR = 0x1
    INTERNAL_ERROR = 0x2
    FLOW_CONTROL_ERROR = 0x3
    SETTINGS_TIMEOUT = 0x4
    STREAM_CLOSED = 0x5
    FRAME_SIZE_ERROR = 0x6
    REFUSED_STREAM = 0x7
    CANCEL = 0x8
    COMPRESSION_ERROR = 0x9
    CONNECT_ERROR = 0xA
    ENHANCE_YOUR_CALM = 0xB
    INADEQUATE_SECURITY = 0xC
    HTTP_1_1_REQUIRED = 0xD

DEFAULT_WINDOW = 65535
DEFAULT_MAX_FRAME = 16384

class H2ConnectionError(Exception):
    def __init__(self, code: ErrorCode, message: str = ""):
        super().__init__(message)
        self.code = code

def serialize_frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return len(payload).to_bytes(3, "big") + bytes([frame_type, flags]) + (stream_id & 0x7FFFFFFF).to_bytes(4, "big") + payload

def serialize_settings(settings: dict[int, int], ack: bool = False) -> bytes:
    payload = b"".join(sid.to_bytes(2, "big") + value.to_bytes(4, "big") for sid, value in settings.items())
    return serialize_frame(Frame.SETTINGS, Flag.ACK if ack else 0, 0, payload)

def serialize_headers(stream_id: int, block: bytes, max_frame: int, end_stream: bool) -> bytes:
    frames = bytearray()
    first, rest = block[:max_frame], block[max_frame:]
    flags = 0 if rest else Flag.END_HEADERS
    if end_stream:
        flags |= Flag.END_STREAM
    frames += serialize_frame(Frame.HEADERS, flags, stream_id, first)
    while rest:
        chunk, rest = rest[:max_frame], rest[max_frame:]
        frames += serialize_frame(Frame.CONTINUATION, 0 if rest else Flag.END_HEADERS, stream_id, chunk)
    return bytes(frames)

def serialize_response(response: Response, encoder: hpack.Encoder, stream_id: int, fields: list[tuple[bytes, bytes]]) -> tuple[bytes, object]:
    block = encoder.encode(fields)
    end_stream = response.body is None
    frames = serialize_headers(stream_id, block, DEFAULT_MAX_FRAME, end_stream)
    return frames, response.body

class Stream:
    def __init__(self, stream_id: int, send_window: int):
        self.id = stream_id
        self.fragments = bytearray()
        self.pending_end_stream = False
        self.fields: list[tuple[bytes, bytes]] | None = None
        self.body = bytearray()
        self.send_window = send_window
        self.closed = False

class H2Connection:
    def __init__(self, reader, writer, app, config, *, scheme, secure, tls):
        self.reader: asyncio.StreamReader = reader
        self.writer: asyncio.StreamWriter = writer
        self.app: App = app
        self.config: Config = config
        self.scheme = scheme
        self.secure = secure
        self.tls = tls
        self.peer = writer.get_extra_info("peername") or ("", 0)

        self.local_settings = {
            Setting.HEADER_TABLE_SIZE: 4096,
            Setting.ENABLE_PUSH: 0,
            Setting.MAX_CONCURRENT_STREAMS: 128,
            Setting.INITIAL_WINDOW_SIZE: DEFAULT_WINDOW,
            Setting.MAX_FRAME_SIZE: DEFAULT_MAX_FRAME
        }
        self.peer_settings = {
            Setting.HEADER_TABLE_SIZE: 4096,
            Setting.INITIAL_WINDOW_SIZE: DEFAULT_WINDOW,
            Setting.MAX_FRAME_SIZE: DEFAULT_MAX_FRAME,
            Setting.ENABLE_PUSH: 1
        }

        self.decoder = hpack.Decoder(self.local_settings[Setting.HEADER_TABLE_SIZE])
        self.encoder = hpack.Encoder(self.peer_settings[Setting.HEADER_TABLE_SIZE])

        self.streams: dict[int, Stream] = {}
        self.last_stream_id = 0
        self.expecting_continuation: int | None = None

        self.conn_send_window = DEFAULT_WINDOW
        self.conn_recv_window = DEFAULT_WINDOW

        self.write_lock = asyncio.Lock()
        self.flow = asyncio.Condition()
        self.tasks: set[asyncio.Task] = set()
        self.goaway_sent = False

    async def run(self, preface_consumed: bool):
        if not preface_consumed:
            preface = await self.reader.readexactly(len(PREFACE))
            if preface != PREFACE:
                return
        self.writer.write(serialize_settings(self.local_settings))
        await self.writer.drain()
        try:
            while True:
                header = await self.reader.readexactly(9)
                length = int.from_bytes(header[:3], "big")
                frame_type, flags = header[3], header[4]
                stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
                if length > self.local_settings[Setting.MAX_FRAME_SIZE]:
                    raise H2ConnectionError(ErrorCode.FRAME_SIZE_ERROR)
                payload = await self.reader.readexactly(length)
                await self.dispatch(frame_type, flags, stream_id, payload)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except H2ConnectionError as exc:
            await self.goaway(exc.code)
        finally:
            for task in list(self.tasks):
                task.cancel()
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def dispatch(self, frame_type, flags, stream_id, payload):
        if self.expecting_continuation is not None and frame_type != Frame.CONTINUATION:
            raise H2ConnectionError(ErrorCode.PROTOCOL_ERROR, "expected CONTINUATION")

        if frame_type == Frame.DATA:
            await self.on_data(flags, stream_id, payload)

        elif frame_type == Frame.HEADERS:
            self.on_headers(flags, stream_id, payload)

        elif frame_type == Frame.CONTINUATION:
            self.on_continuation(flags, stream_id, payload)

        elif frame_type == Frame.SETTINGS:
            await self.on_settings(flags, payload)

        elif frame_type == Frame.WINDOW_UPDATE:
            await self.on_window_update(stream_id, payload)

        elif frame_type == Frame.PING:
            await self.on_ping(flags, payload)

        elif frame_type == Frame.RST_STREAM:
            self.on_rst_stream(stream_id)

        elif frame_type == Frame.PRIORITY:
            if len(payload) != 5:
                raise H2ConnectionError(ErrorCode.FRAME_SIZE_ERROR)

        elif frame_type == Frame.GOAWAY:
            raise H2ConnectionError(ErrorCode.NO_ERROR)

        elif frame_type == Frame.PUSH_PROMISE:
            raise H2ConnectionError(ErrorCode.PROTOCOL_ERROR, "client push not allowed")

    def strip_padding(self, flags, payload) -> bytes:
        if flags & Flag.PADDED:
            pad_length = payload[0]
            payload = payload[1:]
            if pad_length > len(payload):
                raise H2ConnectionError(ErrorCode.PROTOCOL_ERROR, "bad padding")
            payload = payload[:len(payload) - pad_length]
        return payload

    def on_headers(self, flags, stream_id, payload):
        if stream_id == 0 or stream_id % 2 == 0:
            raise H2ConnectionError(ErrorCode.PROTOCOL_ERROR, "invalid stream id")
        block = self.strip_padding(flags, payload)
        if flags & Flag.PRIORITY:
            block = block[5:]
        stream = Stream(stream_id, self.peer_settings[Setting.INITIAL_WINDOW_SIZE])
        stream.pending_end_stream = bool(flags & Flag.END_STREAM)
        stream.fragments += block
        self.streams[stream_id] = stream
        self.last_stream_id = max(self.last_stream_id, stream_id)
        if flags & Flag.END_HEADERS:
            self.finalize_headers(stream)
        else:
            self.expecting_continuation = stream_id

    def on_continuation(self, flags, stream_id, payload):
        if self.expecting_continuation != stream_id:
            raise H2ConnectionError(ErrorCode.PROTOCOL_ERROR, "unexpected CONTINUATION")
        stream = self.streams[stream_id]
        stream.fragments += payload
        if flags & Flag.END_HEADERS:
            self.expecting_continuation = None
            self.finalize_headers(stream)

    def finalize_headers(self, stream):
        try:
            stream.fields = self.decoder.decode(bytes(stream.fragments))
        except hpack.HPACKError:
            raise H2ConnectionError(ErrorCode.COMPRESSION_ERROR)
        stream.fragments = bytearray()
        if stream.pending_end_stream:
            self.spawn_response(stream)

    async def on_data(self, flags, stream_id, payload):
        stream = self.streams.get(stream_id)
        self.conn_recv_window -= len(payload)
        data = self.strip_padding(flags, payload)
        if stream is None or stream.closed:
            await self.replenish(0, len(payload))
            return
        stream.body += data
        if len(stream.body) > self.config.request_max_body_size:
            self.reset_stream(stream_id, ErrorCode.ENHANCE_YOUR_CALM)
            return
        await self.replenish(stream_id, len(payload))
        if flags & Flag.END_STREAM:
            self.spawn_response(stream)

    async def replenish(self, stream_id, amount):
        if amount <= 0:
            return
        self.conn_recv_window += amount
        async with self.write_lock:
            self.writer.write(serialize_frame(Frame.WINDOW_UPDATE, 0, 0, amount.to_bytes(4, "big")))
            if stream_id and stream_id in self.streams and not self.streams[stream_id].closed:
                self.writer.write(serialize_frame(Frame.WINDOW_UPDATE, 0, stream_id, amount.to_bytes(4, "big")))
            await self.writer.drain()

    async def on_settings(self, flags, payload):
        if flags & Flag.ACK:
            return
        if len(payload) % 6 != 0:
            raise H2ConnectionError(ErrorCode.FRAME_SIZE_ERROR)
        old_initial = self.peer_settings[Setting.INITIAL_WINDOW_SIZE]
        for i in range(0, len(payload), 6):
            sid = int.from_bytes(payload[i:i + 2], "big")
            value = int.from_bytes(payload[i + 2:i + 6], "big")
            self.peer_settings[sid] = value
        if Setting.HEADER_TABLE_SIZE in self.peer_settings:
            self.encoder.table.resize(self.peer_settings[Setting.HEADER_TABLE_SIZE])
        new_initial = self.peer_settings[Setting.INITIAL_WINDOW_SIZE]
        if new_initial != old_initial:
            delta = new_initial - old_initial
            async with self.flow:
                for stream in self.streams.values():
                    stream.send_window += delta
                self.flow.notify_all()
        async with self.write_lock:
            self.writer.write(serialize_settings({}, ack=True))
            await self.writer.drain()

    async def on_window_update(self, stream_id, payload):
        if len(payload) != 4:
            raise H2ConnectionError(ErrorCode.FRAME_SIZE_ERROR)
        increment = int.from_bytes(payload, "big") & 0x7FFFFFFF
        if increment == 0:
            if stream_id:
                self.reset_stream(stream_id, ErrorCode.PROTOCOL_ERROR)
                return
            raise H2ConnectionError(ErrorCode.PROTOCOL_ERROR)
        async with self.flow:
            if stream_id == 0:
                self.conn_send_window += increment
            elif stream_id in self.streams:
                self.streams[stream_id].send_window += increment
            self.flow.notify_all()

    async def on_ping(self, flags, payload):
        if flags & Flag.ACK:
            return
        if len(payload) != 8:
            raise H2ConnectionError(ErrorCode.FRAME_SIZE_ERROR)
        async with self.write_lock:
            self.writer.write(serialize_frame(Frame.PING, Flag.ACK, 0, payload))
            await self.writer.drain()

    def on_rst_stream(self, stream_id):
        stream = self.streams.get(stream_id)
        if stream:
            stream.closed = True

    def reset_stream(self, stream_id, code: ErrorCode):
        stream = self.streams.get(stream_id)
        if stream:
            stream.closed = True
        self.writer.write(serialize_frame(Frame.RST_STREAM, 0, stream_id, int(code).to_bytes(4, "big")))

    async def goaway(self, code: ErrorCode):
        if self.goaway_sent:
            return
        self.goaway_sent = True
        payload = self.last_stream_id.to_bytes(4, "big") + int(code).to_bytes(4, "big")
        try:
            self.writer.write(serialize_frame(Frame.GOAWAY, 0, 0, payload))
            await self.writer.drain()
        except (ConnectionError, OSError):
            pass

    def spawn_response(self, stream):
        task = asyncio.ensure_future(self._respond(stream))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def respond(self, stream):
        try:
            request = await parse(bytes(stream.body), protocol="HTTP/2.0", fields=stream.fields, client=self.peer, scheme=self.scheme, secure=self.secure, tls=self.tls)
        except ParseError:
            self.reset_stream(stream.id, ErrorCode.PROTOCOL_ERROR)
            return

        response = await process(self.app, request)
        response.protocol = "HTTP/2.0"
        if stream.closed:
            return

        async with self.write_lock:
            frames, body = await build(response, encoder=self.encoder, stream_id=stream.id)
            self.writer.write(frames)
            await self.writer.drain()
        await self.send_body(stream, body)
        stream.closed = True

    async def send_body(self, stream, body):
        if body is None:
            return
        if not isinstance(body, (bytes, bytearray)):
            with open(body, "rb") as f:
                body = f.read()
        data = bytes(body)
        if not data:
            async with self.write_lock:
                self.writer.write(serialize_frame(Frame.DATA, Flag.END_STREAM, stream.id, b""))
                await self.writer.drain()
            return

        offset = 0
        total = len(data)
        while offset < total:
            async with self.flow:
                while (self.conn_send_window <= 0 or stream.send_window <= 0) and not stream.closed:
                    await self.flow.wait()
                if stream.closed:
                    return
                allowed = min(self.conn_send_window, stream.send_window, self.peer_settings[Setting.MAX_FRAME_SIZE], total - offset)
                chunk = data[offset:offset + allowed]
                self.conn_send_window -= len(chunk)
                stream.send_window -= len(chunk)
            offset += len(chunk)
            flags = Flag.END_STREAM if offset >= total else 0
            async with self.write_lock:
                self.writer.write(serialize_frame(Frame.DATA, flags, stream.id, chunk))
                await self.writer.drain()

async def serve_connection(reader, writer, app, config, *, scheme="https", secure=True, tls: TLSInfo | None = None, preface_consumed=False):
    connection = H2Connection(reader, writer, app, config, scheme=scheme, secure=secure, tls=tls)
    await connection.run(preface_consumed)
