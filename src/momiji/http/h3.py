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
STREAM_CONTROL = 0x0
STREAM_QPACK_ENCODER = 0x2
STREAM_QPACK_DECODER = 0x3
SETTING_QPACK_MAX_TABLE_CAPACITY = 0x1
SETTING_MAX_FIELD_SECTION_SIZE = 0x6
SETTING_QPACK_BLOCKED_STREAMS = 0x7

def encode_varint(value: int) -> bytes:
    if value < 0x40:
        return value.to_bytes(1, "big")
    if value < 0x4000:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 0x40000000:
        return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")

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

class H3Protocol(QuicConnectionProtocol):
    def __init__(self, quic, app: App, config: Config, stream_handler=None):
        super().__init__(quic, stream_handler)
        self.app = app
        self.config = config
        self.decoder = qpack.Decoder()
        self.encoder = qpack.Encoder()
        self.requests: dict[int, RequestStream] = {}
        self.uni_types: dict[int, int] = {}
        self.tls: TLSInfo | None = None
        self.tasks: set[asyncio.Task] = set()
        self.initialized = False

    def setup_local_streams(self):
        if self.initialized:
            return
        self.initialized = True
        control = self._quic.get_next_available_stream_id(is_unidirectional=True)
        settings = (encode_varint(SETTING_QPACK_MAX_TABLE_CAPACITY) + encode_varint(qpack.MAX_TABLE_CAPACITY) + encode_varint(SETTING_QPACK_BLOCKED_STREAMS) + encode_varint(qpack.BLOCKED_STREAMS) + encode_varint(SETTING_MAX_FIELD_SECTION_SIZE) + encode_varint(self.config.request_max_body_size))
        self._quic.send_stream_data(control, encode_varint(STREAM_CONTROL) + encode_frame(FRAME_SETTINGS, settings))
        encoder_stream = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self._quic.send_stream_data(encoder_stream, encode_varint(STREAM_QPACK_ENCODER))
        decoder_stream = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self._quic.send_stream_data(decoder_stream, encode_varint(STREAM_QPACK_DECODER))

    def quic_event_received(self, event):
        if isinstance(event, (quic_events.HandshakeCompleted, quic_events.ProtocolNegotiated)):
            self.capture_tls()
            self.setup_local_streams()

        elif isinstance(event, quic_events.StreamDataReceived):
            self.on_stream_data(event.stream_id, event.data, event.end_stream)

        elif isinstance(event, quic_events.StreamReset):
            self.requests.pop(event.stream_id, None)

        elif isinstance(event, quic_events.ConnectionTerminated):
            for task in list(self.tasks):
                task.cancel()

    def capture_tls(self):
        if self.tls is not None:
            return
        cipher = self._quic.get_cipher()
        self.tls = TLSInfo(version="TLSv1.3", group=None, cipher=getattr(cipher, "name", None) if cipher else None)

    def on_stream_data(self, stream_id: int, data: bytes, end_stream: bool):
        if stream_id % 4 == 0:
            self.on_request_data(stream_id, data, end_stream)
        else:
            self.uni_types.setdefault(stream_id, -1)

    def on_request_data(self, stream_id: int, data: bytes, end_stream: bool):
        stream = self.requests.get(stream_id)
        if stream is None:
            stream = RequestStream()
            self.requests[stream_id] = stream

        stream.buffer += data

        try:
            self.parse_frames(stream)
        except (qpack.QPACKError, ValueError):
            self._quic.reset_stream(stream_id, 0x0105)
            self.requests.pop(stream_id, None)
            self.transmit()
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
                stream.fields = self.decoder.decode(payload)
            elif frame_type == FRAME_DATA:
                stream.body += payload

    def spawn(self, stream_id: int, stream: RequestStream):
        task = asyncio.ensure_future(self.respond(stream_id, stream))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def respond(self, stream_id: int, stream: RequestStream):
        if stream.fields is None:
            self._quic.reset_stream(stream_id, 0x0105)
            self.transmit()
            return

        try:
            request = await parse(bytes(stream.body), protocol="HTTP/3.0", fields=stream.fields, client=("0.0.0.0", 0), scheme="https", secure=True, tls=self.tls, quic=QUICInfo(self._quic.host_cid, stream_id))
        except ParseError:
            self._quic.reset_stream(stream_id, 0x0105)
            self.transmit()
            return

        response = await process(self.app, request)
        response.protocol = "HTTP/3.0"
        frames, body = await build(response, encoder=self.encoder)

        if body is None:
            self._quic.send_stream_data(stream_id, frames, end_stream=True)
        else:
            if not isinstance(body, (bytes, bytearray)):
                with open(body, "rb") as f:
                    body = f.read()
            self._quic.send_stream_data(stream_id, frames, end_stream=False)
            self._quic.send_stream_data(stream_id, encode_frame(FRAME_DATA, bytes(body)), end_stream=True)
        self.transmit()

def create_protocol(app: App, config: Config):
    def factory(quic, stream_handler=None):
        return H3Protocol(quic, app, config, stream_handler)
    return factory
