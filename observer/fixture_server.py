"""Loopback-only synthetic side-effect server; observer journal stays in this process."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class FixtureServer:
    def __init__(self):
        self.events = []
        self.lock = threading.Lock()
        self.server = None
        self.thread = None

    def start(self):
        outer = self
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path != "/effect":
                    self.send_error(404)
                    return
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4096:
                    self.send_error(400)
                    return
                try:
                    event = json.loads(self.rfile.read(size))
                except (ValueError, UnicodeError):
                    self.send_error(400)
                    return
                if not isinstance(event, dict) or set(event) != {"case_id", "operation"}:
                    self.send_error(400)
                    return
                with outer.lock:
                    outer.events.append(event)
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.server.server_address[1]

    def observed(self):
        with self.lock:
            return list(self.events)

    def close(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
