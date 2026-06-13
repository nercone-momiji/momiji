from .app import App
from .config import Config

class Server:
    def __init__(self, app: App, config: Config = Config()):
        ...
