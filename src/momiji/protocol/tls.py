from enum import Enum
from typing import Literal
from dataclasses import dataclass

class Group(Enum):
    ...

class Cipher(Enum):
    ...

@dataclass
class TLSInfo:
    version: Literal["1.0", "1.1", "1.2", "1.3"]
    group: Group
    cipher: Cipher
