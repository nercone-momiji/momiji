from __future__ import annotations

from . import huffman
from .hpack import encode_integer, decode_integer
from .qpack_table import QPACK_STATIC_TABLE

MAX_TABLE_CAPACITY = 0
BLOCKED_STREAMS = 0

STATIC_INDEX: dict[tuple[bytes, bytes], int] = {}
STATIC_NAME_INDEX: dict[bytes, int] = {}
for _i, (_n, _v) in enumerate(QPACK_STATIC_TABLE):
    STATIC_INDEX.setdefault((_n, _v), _i)
    STATIC_NAME_INDEX.setdefault(_n, _i)

class QPACKError(Exception):
    pass

def decode_string(data: bytes, pos: int, prefix_bits: int) -> tuple[bytes, int]:
    is_huffman = bool(data[pos] & (1 << prefix_bits))
    length, pos = decode_integer(data, pos, prefix_bits)
    raw = data[pos:pos + length]
    if len(raw) != length:
        raise QPACKError("truncated string")
    pos += length
    return (huffman.decode(raw) if is_huffman else bytes(raw)), pos

def encode_string(value: bytes, prefix_bits: int, flags: int = 0) -> bytearray:
    encoded = huffman.encode(value)
    if len(encoded) < len(value):
        field = encode_integer(len(encoded), prefix_bits)
        field[0] |= flags | (1 << prefix_bits)
        return field + encoded
    field = encode_integer(len(value), prefix_bits)
    field[0] |= flags
    return field + value

class Decoder:
    def static(self, index: int) -> tuple[bytes, bytes]:
        if index >= len(QPACK_STATIC_TABLE):
            raise QPACKError(f"static index {index} out of range")
        return QPACK_STATIC_TABLE[index]

    def decode(self, block: bytes) -> list[tuple[bytes, bytes]]:
        if not block:
            raise QPACKError("empty header block")
        pos = 0
        required_insert_count, pos = decode_integer(block, pos, 8)
        if required_insert_count != 0:
            raise QPACKError("dynamic table not supported (capacity 0)")
        if pos >= len(block):
            raise QPACKError("truncated header block prefix")
        sign = bool(block[pos] & 0x80)
        delta_base, pos = decode_integer(block, pos, 7)
        if sign and delta_base != 0:
            raise QPACKError("non-zero negative base disallowed without dynamic table")

        fields: list[tuple[bytes, bytes]] = []
        size = len(block)
        while pos < size:
            byte = block[pos]

            if byte & 0x80:
                static = byte & 0x40
                index, pos = decode_integer(block, pos, 6)
                if not static:
                    raise QPACKError("dynamic reference unsupported")
                fields.append(self.static(index))

            elif byte & 0x40:
                static = byte & 0x10
                index, pos = decode_integer(block, pos, 4)
                if not static:
                    raise QPACKError("dynamic reference unsupported")
                name = self.static(index)[0]
                value, pos = decode_string(block, pos, 7)
                fields.append((name, value))

            elif byte & 0x20:
                name, pos = decode_string(block, pos, 3)
                value, pos = decode_string(block, pos, 7)
                fields.append((name, value))

            else:
                raise QPACKError("post-base / dynamic reference unsupported")

        return fields

class Encoder:
    def encode(self, fields: list[tuple[bytes, bytes]]) -> bytes:
        out = bytearray(b"\x00\x00")

        for name, value in fields:
            name = name.lower()
            full = STATIC_INDEX.get((name, value))

            if full is not None:
                field = encode_integer(full, 6)
                field[0] |= 0xC0
                out += field
                continue

            name_index = STATIC_NAME_INDEX.get(name)
            if name_index is not None:
                field = encode_integer(name_index, 4)
                field[0] |= 0x50
                out += field
                out += encode_string(value, 7)

            else:
                out += encode_string(name, 3, flags=0x20)
                out += encode_string(value, 7)

        return bytes(out)
