from __future__ import annotations

from collections import deque

from . import huffman

STATIC_TABLE: list[tuple[bytes, bytes]] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b"")
]

STATIC_INDEX: dict[tuple[bytes, bytes], int] = {}
STATIC_NAME_INDEX: dict[bytes, int] = {}
for _i, (_n, _v) in enumerate(STATIC_TABLE, start=1):
    STATIC_INDEX.setdefault((_n, _v), _i)
    STATIC_NAME_INDEX.setdefault(_n, _i)

class HPACKError(Exception):
    pass

def encode_integer(value: int, prefix_bits: int) -> bytearray:
    limit = (1 << prefix_bits) - 1
    out = bytearray()
    if value < limit:
        out.append(value)
        return out
    out.append(limit)
    value -= limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return out

MAX_INTEGER_VALUE = (1 << 32) - 1
MAX_INTEGER_BYTES = 8

def decode_integer(data: bytes, pos: int, prefix_bits: int) -> tuple[int, int]:
    limit = (1 << prefix_bits) - 1
    if pos >= len(data):
        raise HPACKError("truncated integer")
    value = data[pos] & limit
    pos += 1
    if value < limit:
        return value, pos
    shift = 0
    consumed = 0
    while True:
        if pos >= len(data):
            raise HPACKError("truncated integer continuation")
        byte = data[pos]
        pos += 1
        consumed += 1
        if consumed > MAX_INTEGER_BYTES:
            raise HPACKError("integer encoding too long")
        value += (byte & 0x7F) << shift
        if value > MAX_INTEGER_VALUE:
            raise HPACKError("integer value too large")
        shift += 7
        if not byte & 0x80:
            break
    return value, pos

def encode_string(value: bytes, huffman_encode: bool = True) -> bytearray:
    if huffman_encode:
        encoded = huffman.encode(value)
        if len(encoded) < len(value):
            out = encode_integer(len(encoded), 7)
            out[0] |= 0x80
            out += encoded
            return out
    out = encode_integer(len(value), 7)
    out += value
    return out

def decode_string(data: bytes, pos: int) -> tuple[bytes, int]:
    if pos >= len(data):
        raise HPACKError("truncated string literal header")
    is_huffman = bool(data[pos] & 0x80)
    length, pos = decode_integer(data, pos, 7)
    raw = data[pos:pos + length]
    if len(raw) != length:
        raise HPACKError("truncated string literal")
    pos += length
    try:
        decoded = huffman.decode(raw) if is_huffman else bytes(raw)
    except (ValueError, KeyError) as exc:
        raise HPACKError(f"invalid huffman sequence: {exc}")
    return decoded, pos

class DynamicTable:
    def __init__(self, max_size: int = 4096):
        self.entries: deque[tuple[bytes, bytes]] = deque()
        self.size = 0
        self.max_size = max_size

    def entry_size(self, name: bytes, value: bytes) -> int:
        return len(name) + len(value) + 32

    def add(self, name: bytes, value: bytes):
        entry_size = self.entry_size(name, value)
        self.evict_to(self.max_size - entry_size)
        if entry_size > self.max_size:
            return
        self.entries.appendleft((name, value))
        self.size += entry_size

    def evict_to(self, target: int):
        while self.size > target and self.entries:
            name, value = self.entries.pop()
            self.size -= self.entry_size(name, value)

    def resize(self, max_size: int):
        self.max_size = max_size
        self.evict_to(max_size)

    def __len__(self) -> int:
        return len(self.entries)

    def __getitem__(self, index: int) -> tuple[bytes, bytes]:
        return self.entries[index]

class Decoder:
    def __init__(self, max_size: int = 4096):
        self.table = DynamicTable(max_size)
        self.max_allowed_size = max_size

    def get(self, index: int) -> tuple[bytes, bytes]:
        if index == 0:
            raise HPACKError("invalid header index 0")
        if index <= len(STATIC_TABLE):
            return STATIC_TABLE[index - 1]
        dyn_index = index - len(STATIC_TABLE) - 1
        if dyn_index >= len(self.table):
            raise HPACKError(f"index {index} out of range")
        return self.table[dyn_index]

    def decode(self, block: bytes) -> list[tuple[bytes, bytes]]:
        headers: list[tuple[bytes, bytes]] = []
        pos = 0
        size = len(block)
        seen_non_size_update = False

        while pos < size:
            byte = block[pos]

            if byte & 0x80:
                index, pos = decode_integer(block, pos, 7)
                headers.append(self.get(index))
                seen_non_size_update = True

            elif byte & 0x40:
                index, pos = decode_integer(block, pos, 6)
                name, value, pos = self.read_literal(block, pos, index)
                self.table.add(name, value)
                headers.append((name, value))
                seen_non_size_update = True

            elif byte & 0x20:
                if seen_non_size_update:
                    raise HPACKError("dynamic table size update not at start of block")
                new_size, pos = decode_integer(block, pos, 5)
                if new_size > self.max_allowed_size:
                    raise HPACKError("dynamic table size update exceeds limit")
                self.table.resize(new_size)

            else:
                index, pos = decode_integer(block, pos, 4)
                name, value, pos = self.read_literal(block, pos, index)
                headers.append((name, value))
                seen_non_size_update = True

        return headers

    def read_literal(self, block: bytes, pos: int, index: int) -> tuple[bytes, bytes, int]:
        if index == 0:
            name, pos = decode_string(block, pos)
        else:
            name = self.get(index)[0]
        value, pos = decode_string(block, pos)
        return name, value, pos

class Encoder:
    def __init__(self, max_size: int = 4096):
        self.table = DynamicTable(max_size)
        self.pending_size_updates: list[int] = []

    def resize(self, max_size: int):
        if max_size == self.table.max_size:
            return
        self.table.resize(max_size)
        self.pending_size_updates.append(max_size)

    def find(self, name: bytes, value: bytes) -> tuple[int | None, int | None]:
        full = STATIC_INDEX.get((name, value))
        if full is not None:
            return full, full

        name_index = STATIC_NAME_INDEX.get(name)
        dyn_offset = len(STATIC_TABLE)

        for i, (n, v) in enumerate(self.table.entries):
            if n == name:
                idx = dyn_offset + i + 1
                if v == value:
                    return idx, idx
                if name_index is None:
                    name_index = idx

        return None, name_index

    def encode(self, headers: list[tuple[bytes, bytes]]) -> bytes:
        out = bytearray()

        for new_size in self.pending_size_updates:
            field = encode_integer(new_size, 5)
            field[0] |= 0x20
            out += field
        self.pending_size_updates.clear()

        for name, value in headers:
            name = name.lower()
            full_index, name_index = self.find(name, value)

            if full_index is not None:
                field = encode_integer(full_index, 7)
                field[0] |= 0x80
                out += field

            elif name_index is not None:
                field = encode_integer(name_index, 6)
                field[0] |= 0x40
                out += field
                out += encode_string(value)
                self.table.add(name, value)

            else:
                out.append(0x40)
                out += encode_string(name)
                out += encode_string(value)
                self.table.add(name, value)

        return bytes(out)
