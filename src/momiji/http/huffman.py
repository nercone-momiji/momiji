from __future__ import annotations

from .huffman_table import HUFFMAN_TABLE

EOS = 256

def build_decode_trie() -> dict:
    root: dict = {}
    for symbol, (code, length) in enumerate(HUFFMAN_TABLE):
        node = root
        for shift in range(length - 1, -1, -1):
            bit = (code >> shift) & 1
            if shift == 0:
                node[bit] = symbol
            else:
                node = node.setdefault(bit, {})
    return root

DECODE_TRIE = build_decode_trie()

def encode(data: bytes) -> bytes:
    buffer = 0
    bits = 0
    out = bytearray()

    for byte in data:
        code, length = HUFFMAN_TABLE[byte]
        buffer = (buffer << length) | code
        bits += length
        while bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)

    if bits:
        out.append(((buffer << (8 - bits)) | ((1 << (8 - bits)) - 1)) & 0xFF)

    return bytes(out)

def decode(data: bytes) -> bytes:
    out = bytearray()
    node = DECODE_TRIE
    padding = True

    for byte in data:
        for shift in range(7, -1, -1):
            bit = (byte >> shift) & 1
            node = node[bit]
            if isinstance(node, int):
                if node == EOS:
                    raise ValueError("EOS symbol encountered in Huffman sequence")
                out.append(node)
                node = DECODE_TRIE
                padding = True

            else:
                padding = padding and bit == 1

    if node is not DECODE_TRIE and not padding:
        raise ValueError("invalid Huffman padding")

    return bytes(out)
