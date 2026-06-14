from dataclasses import dataclass

@dataclass
class QUICInfo:
    connection_id: bytes
    stream_id: int
