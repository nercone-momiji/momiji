from .models import Listener

class Handler:
    def __init__(self, listener: Listener):
        self.listener = listener

    def start(self):
        ...

    def stop(self):
        ...
