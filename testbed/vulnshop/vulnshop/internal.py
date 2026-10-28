import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import config, store

_ROUTES = {
    "/": {"service": "inventory-internal", "status": "ok"},
    "/internal/config": {
        "service": "inventory-internal",
        "warehouse": "WH-TEST-01",
        "api_token": "fake-internal-token-0000",
        "note": store.flag("V10"),
    },
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        body = _ROUTES.get(path)
        status = 200 if body is not None else 404
        raw = json.dumps(body if body is not None else {"error": "not found"}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


def start(port):
    """Bind PORT+1 on loopback only; raises OSError when the port is busy."""
    server = ThreadingHTTPServer((config.BIND_ADDRESS, port + 1), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
