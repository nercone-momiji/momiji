from .http import Request, Response
from .config import Config

class App:
    def __init__(self, config: Config):
        pass

    def __call__(self, request: Request) -> Response:
        return Response("Hello, World! This is Response from Default Momiji Application.".encode())
