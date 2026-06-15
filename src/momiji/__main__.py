from .app import App, Response
from .server import Server

class DemoApp(App):
    def __call__(self, request):
        return Response("It works! This is Response from Demo.".encode(), content_type="text/plain")

def main():
    print("Starting server... Try access it to http://localhost:80/")
    server = Server(DemoApp())
    server.run()

if __name__ == "__main__":
    main()
