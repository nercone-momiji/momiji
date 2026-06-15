import os
from http import HTTPStatus
from dataclasses import dataclass

from .models import Request, Response

@dataclass
class H2Info:
    connection_id: bytes
    stream_id: int

class H2:
    ...
