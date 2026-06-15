from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from qh3.asyncio.protocol import QuicConnectionProtocol
from qh3.quic import events as quic_events

from . import qpack
from .models import Response, TLSInfo, QUICInfo
from .parse import parse, ParseError
from .process import process
from .build import build

if TYPE_CHECKING:
    from ..app import App
    from ..config import Config

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_SETTINGS = 0x4
FRAME_GOAWAY = 0x7
STREAM_CONTROL = 0x0
STREAM_PUSH = 0x1
STREAM_QPACK_ENCODER = 0x2
STREAM_QPACK_DECODER = 0x3
SETTING_QPACK_MAX_TABLE_CAPACITY = 0x1
SETTING_MAX_FIELD_SECTION_SIZE = 0x6
SETTING_QPACK_BLOCKED_STREAMS = 0x7

H3_NO_ERROR = 0x0100
H3_GENERAL_PROTOCOL_ERROR = 0x0101
H3_INTERNAL_ERROR = 0x0102
H3_STREAM_CREATION_ERROR = 0x0103
H3_CLOSED_CRITICAL_STREAM = 0x0104
H3_FRAME_UNEXPECTED = 0x0105
H3_FRAME_ERROR = 0x0106
H3_MESSAGE_ERROR = 0x010E

DEFAULT_MAX_FIELD_SECTION_SIZE = 256 * 1024

def encode_varint(value: int) -> bytes:
    if value < 0x40:
        return value.to_bytes(1, "big")
    if value < 0x4000:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 0x40000000:
        return (value | 0x80000000).to_bytes(4, "big")
    if value < (1 << 62):
        return (value | 0xC000000000000000).to_bytes(8, "big")
    raise ValueError("varint out of range")

def decode_varint(data: bytes, pos: int) -> tuple[int, int] | None:
    if pos >= len(data):
        return None
    length = 1 << (data[pos] >> 6)
    if pos + length > len(data):
        return None
    value = data[pos] & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[pos + i]
    return value, pos + length

def encode_frame(frame_type: int, payload: bytes) -> bytes:
    return encode_varint(frame_type) + encode_varint(len(payload)) + payload

def serialize_response(response: Response, encoder: qpack.Encoder, fields: list[tuple[bytes, bytes]]) -> tuple[bytes, object]:
    block = encoder.encode(fields)
    return encode_frame(FRAME_HEADERS, block), response.body

class RequestStream:
    def __init__(self):
        self.buffer = bytearray()
        self.fields: list[tuple[bytes, bytes]] | None = None
        self.body = bytearray()
        self.dispatched = False
        self.headers_done = False
        self.errored = False

class UniStream:
    def __init__(self):
        self.buffer = bytearray()
        self.kind: int | None = None

class H3Protocol(QuicConnectionProtocol):
    def __init__(self, quic, app: "App", config: "Config", stream_handler=None):
        super().__init__(quic, stream_handler)
        self.app = app
        self.config = config
        self.decoder = qpack.Decoder()
        self.encoder = qpack.Encoder()
        self.requests: dict[int, RequestStream] = {}
        self.uni_streams: dict[int, UniStream] = {}
        self.peer_control_seen = False
        self.peer_qpack_encoder_seen = False
        self.peer_qpack_decoder_seen = False
        self.peer_max_field_section_size = DEFAULT_MAX_FIELD_SECTION_SIZE
        self.tls: TLSInfo | None = None
        self.tasks: set[asyncio.Task] = set()
        self.initialized = False
        self.client_address: tuple = ("0.0.0.0", 0)

    def connection_made(self, transport):
        super().connection_made(transport)

    def setup_local_streams(self):
        if self.initialized:
            return
        self.initialized = True
        control = self._quic.get_next_available_stream_id(is_unidirectional=True)
        settings = encode_varint(SETTING_QPACK_MAX_TABLE_CAPACITY) + encode_varint(qpack.MAX_TABLE_CAPACITY) + encode_varint(SETTING_QPACK_BLOCKED_STREAMS) + encode_varint(qpack.BLOCKED_STREAMS) + encode_varint(SETTING_MAX_FIELD_SECTION_SIZE) + encode_varint(self.config.request_max_header_size)
        self._quic.send_stream_data(control, encode_varint(STREAM_CONTROL) + encode_frame(FRAME_SETTINGS, settings))
        encoder_stream = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self._quic.send_stream_data(encoder_stream, encode_varint(STREAM_QPACK_ENCODER))
        decoder_stream = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self._quic.send_stream_data(decoder_stream, encode_varint(STREAM_QPACK_DECODER))

    def quic_event_received(self, event):
        if isinstance(event, (quic_events.HandshakeCompleted, quic_events.ProtocolNegotiated)):
            self.capture_tls()
            self.capture_peer()
            self.setup_local_streams()

        elif isinstance(event, quic_events.StreamDataReceived):
            self.on_stream_data(event.stream_id, event.data, event.end_stream)

        elif isinstance(event, quic_events.StreamReset):
            self.requests.pop(event.stream_id, None)
            self.uni_streams.pop(event.stream_id, None)

        elif isinstance(event, quic_events.ConnectionTerminated):
            for task in list(self.tasks):
                task.cancel()

    def capture_tls(self):
        if self.tls is not None:
            return
        cipher = self._quic.get_cipher()
        self.tls = TLSInfo(version="TLSv1.3", group=None, cipher=getattr(cipher, "name", None) if cipher else None)

    def capture_peer(self):
        try:
            peer = self._transport.get_extra_info("peername")
            if peer:
                self.client_address = peer
        except Exception:
            pass

    def on_stream_data(self, stream_id: int, data: bytes, end_stream: bool):
        kind = stream_id & 0x3
        if kind == 0:
            self.on_request_data(stream_id, data, end_stream)
        elif kind == 2:
            self.on_uni_data(stream_id, data, end_stream)

    def on_uni_data(self, stream_id: int, data: bytes, end_stream: bool):
        stream = self.uni_streams.get(stream_id)
        if stream is None:
            stream = UniStream()
            self.uni_streams[stream_id] = stream

        stream.buffer += data

        if stream.kind is None:
            result = decode_varint(stream.buffer, 0)
            if result is None:
                return
            kind, pos = result
            stream.kind = kind
            del stream.buffer[:pos]

            if kind == STREAM_CONTROL:
                if self.peer_control_seen:
                    self.terminate(H3_STREAM_CREATION_ERROR, "duplicate control stream")
                    return
                self.peer_control_seen = True

            elif kind == STREAM_QPACK_ENCODER:
                if self.peer_qpack_encoder_seen:
                    self.terminate(H3_STREAM_CREATION_ERROR, "duplicate qpack encoder")
                    return
                self.peer_qpack_encoder_seen = True

            elif kind == STREAM_QPACK_DECODER:
                if self.peer_qpack_decoder_seen:
                    self.terminate(H3_STREAM_CREATION_ERROR, "duplicate qpack decoder")
                    return
                self.peer_qpack_decoder_seen = True

            elif kind == STREAM_PUSH:
                self._quic.stop_stream(stream_id, H3_STREAM_CREATION_ERROR)
                self.transmit()
                self.uni_streams.pop(stream_id, None)
                return

        if stream.kind == STREAM_CONTROL:
            try:
                self.parse_control(stream)
            except Exception:
                self.terminate(H3_FRAME_ERROR, "control parse error")
                return
            if end_stream:
                self.terminate(H3_CLOSED_CRITICAL_STREAM, "control stream closed")
                return

        elif stream.kind in (STREAM_QPACK_ENCODER, STREAM_QPACK_DECODER):
            stream.buffer.clear()
            if end_stream:
                self.terminate(H3_CLOSED_CRITICAL_STREAM, "qpack stream closed")
                return

        else:
            stream.buffer.clear()

    def parse_control(self, stream: UniStream):
        while True:
            type_result = decode_varint(stream.buffer, 0)
            if type_result is None:
                return
            frame_type, pos = type_result
            length_result = decode_varint(stream.buffer, pos)
            if length_result is None:
                return
            length, pos = length_result
            if len(stream.buffer) - pos < length:
                return

            payload = bytes(stream.buffer[pos:pos + length])
            del stream.buffer[:pos + length]

            if not hasattr(stream, "control_started"):
                if frame_type != FRAME_SETTINGS:
                    raise ValueError("first control frame must be SETTINGS")
                stream.control_started = True
                self.apply_settings(payload)
            else:
                if frame_type == FRAME_SETTINGS:
                    raise ValueError("duplicate SETTINGS")

    def apply_settings(self, payload: bytes):
        pos = 0
        while pos < len(payload):
            t_result = decode_varint(payload, pos)
            if t_result is None:
                return
            ident, pos = t_result
            v_result = decode_varint(payload, pos)
            if v_result is None:
                return
            value, pos = v_result

            if ident == SETTING_MAX_FIELD_SECTION_SIZE:
                self.peer_max_field_section_size = value
            elif ident == SETTING_QPACK_MAX_TABLE_CAPACITY:
                pass
            elif ident == SETTING_QPACK_BLOCKED_STREAMS:
                pass

    def terminate(self, error_code: int, reason: str = ""):
        try:
            self._quic.close(error_code=error_code, reason_phrase=reason)
            self.transmit()
        except Exception:
            pass

    def on_request_data(self, stream_id: int, data: bytes, end_stream: bool):
        stream = self.requests.get(stream_id)
        if stream is None:
            stream = RequestStream()
            self.requests[stream_id] = stream

        if stream.errored:
            return

        stream.buffer += data

        try:
            self.parse_frames(stream)
        except (qpack.QPACKError, ValueError):
            stream.errored = True
            try:
                self._quic.reset_stream(stream_id, H3_MESSAGE_ERROR)
            except Exception:
                pass
            self.transmit()
            self.requests.pop(stream_id, None)
            return

        if end_stream and not stream.dispatched:
            stream.dispatched = True
            self.spawn(stream_id, stream)

    def parse_frames(self, stream: RequestStream):
        while True:
            type_result = decode_varint(stream.buffer, 0)
            if type_result is None:
                return

            frame_type, pos = type_result

            length_result = decode_varint(stream.buffer, pos)
            if length_result is None:
                return

            length, pos = length_result
            if len(stream.buffer) - pos < length:
                return

            payload = bytes(stream.buffer[pos:pos + length])

            del stream.buffer[:pos + length]

            if frame_type == FRAME_HEADERS:
                if not stream.headers_done:
                    stream.fields = self.decoder.decode(payload)
                    stream.headers_done = True

            elif frame_type == FRAME_DATA:
                if not stream.headers_done:
                    raise ValueError("DATA before HEADERS")
                if len(stream.body) + len(payload) > self.config.request_max_body_size:
                    raise ValueError("body too large")
                stream.body += payload

    def spawn(self, stream_id: int, stream: RequestStream):
        task = asyncio.ensure_future(self.respond(stream_id, stream))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def respond(self, stream_id: int, stream: RequestStream):
        if stream.fields is None:
            try:
                self._quic.reset_stream(stream_id, H3_MESSAGE_ERROR)
            except Exception:
                pass
            self.transmit()
            return

        try:
            request = await parse(bytes(stream.body), protocol="HTTP/3.0", fields=stream.fields, client=self.client_address, scheme="https", secure=True, tls=self.tls, quic=QUICInfo(self._quic.host_cid, stream_id))
        except ParseError:
            try:
                self._quic.reset_stream(stream_id, H3_MESSAGE_ERROR)
            except Exception:
                pass
            self.transmit()
            return

        try:
            response = await process(self.app, request)
        except Exception:
            try:
                self._quic.reset_stream(stream_id, H3_INTERNAL_ERROR)
            except Exception:
                pass
            self.transmit()
            return

        response.protocol = "HTTP/3.0"

        try:
            frames, body = await build(response, encoder=self.encoder)
        except Exception:
            try:
                self._quic.reset_stream(stream_id, H3_INTERNAL_ERROR)
            except Exception:
                pass
            self.transmit()
            return

        if body is None:
            self._quic.send_stream_data(stream_id, frames, end_stream=True)
            self.transmit()
            return

        self._quic.send_stream_data(stream_id, frames, end_stream=False)

        if isinstance(body, (bytes, bytearray)):
            self._quic.send_stream_data(stream_id, encode_frame(FRAME_DATA, bytes(body)), end_stream=True)
            self.transmit()
            return

        loop = asyncio.get_event_loop()
        try:
            fd = await loop.run_in_executor(None, lambda: open(body, "rb"))
        except OSError:
            self._quic.send_stream_data(stream_id, encode_frame(FRAME_DATA, b""), end_stream=True)
            self.transmit()
            return

        try:
            pending = await loop.run_in_executor(None, fd.read, 65536)
            if not pending:
                self._quic.send_stream_data(stream_id, encode_frame(FRAME_DATA, b""), end_stream=True)
                self.transmit()
                return

            while pending:
                next_chunk = await loop.run_in_executor(None, fd.read, 65536)
                is_last = not next_chunk
                self._quic.send_stream_data(stream_id, encode_frame(FRAME_DATA, pending), end_stream=is_last)
                self.transmit()
                pending = next_chunk
        finally:
            await loop.run_in_executor(None, fd.close)

def create_protocol(app: "App", config: "Config"):
    def factory(quic, stream_handler=None):
        return H3Protocol(quic, app, config, stream_handler)
    return factory
