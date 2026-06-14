from .app import App
from .config import Config

class Server:
    def __init__(self, app: App, config: Config | None = None):
        if config is None:
            config = Config()
        ...

    def run(self):
        ...

    def serve(self):
        ...
