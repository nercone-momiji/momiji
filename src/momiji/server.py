from .app import App
from .config import Config

class Server:
    def __init__(self, app: type[App] | App, config: Config | None = None):
        if config is None:
            config = Config()
        self.config = config
        self.app = app(config) if isinstance(app, type) else app

    def run(self):
        ...

    async def serve(self):
        ...
