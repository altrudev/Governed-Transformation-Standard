"""Prototype bounded Unix event receiver. No signing endpoint or remote admin API."""
import json
import os
import pathlib
import socketserver
import threading

ALLOWED = {"case_id", "operation", "challenge"}

class Receiver(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    def __init__(self, socket_path, challenge):
        self.challenge = challenge
        self.events = []
        self.rejected = 0
        self.lock = threading.Lock()
        super().__init__(str(socket_path), Handler)

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            data = self.rfile.readline(4097)
            if not data.endswith(b"\n") or len(data) > 4096:
                raise ValueError("size or framing")
            event = json.loads(data)
            if (not isinstance(event, dict) or set(event) != ALLOWED
                or event["operation"] != "synthetic-effect"
                or not isinstance(event["case_id"], str)
                or len(event["case_id"]) > 128
                or event["challenge"] != self.server.challenge):
                raise ValueError("invalid event")
            with self.server.lock:
                if any(e["case_id"] == event["case_id"] for e in self.server.events):
                    raise ValueError("duplicate")
                self.server.events.append(event)
            self.wfile.write(b'{"status":"recorded"}\n')
        except (ValueError, UnicodeError, OSError, TimeoutError):
            with self.server.lock:
                self.server.rejected += 1

def serve(path, challenge):
    location = pathlib.Path(path)
    if not location.parent.is_dir():
        raise RuntimeError("socket parent unavailable")
    if location.exists():
        raise RuntimeError("refusing existing socket path")
    server = Receiver(location, challenge)
    os.chmod(location, 0o600)
    try:
        server.serve_forever()
    finally:
        server.server_close()

def main():
    # Fail closed without operator configured challenge and socket directory.
    challenge = os.environ.get("GTS_OBSERVER_CHALLENGE")
    path = os.environ.get("GTS_OBSERVER_SOCKET")
    if not challenge or len(challenge) < 32 or not path:
        raise SystemExit("observer service requires configured challenge and socket")
    serve(path, challenge)

if __name__ == "__main__":
    main()
