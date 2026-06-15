import os
from http import HTTPStatus
from dataclasses import dataclass

from .models import Request, Response

@dataclass
class H3Info:
    connection_id: bytes
    stream_id: int

class H3:
    ...
