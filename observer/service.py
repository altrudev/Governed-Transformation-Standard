"""Prototype bounded Unix event receiver. No signing endpoint or remote admin API."""
import json
import os
import pathlib
import pwd
import socketserver
import socket
import struct
import threading
from observer.challenge_authority import ChallengeAuthority

ALLOWED = {"case_id", "operation", "challenge"}

class Receiver(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    def __init__(self, socket_path, challenge, allowed_uids=None, authority=None, durable_events=None):
        self.challenge = challenge
        self.authority = authority
        self.durable_events = durable_events
        self.allowed_uids = frozenset(allowed_uids if allowed_uids is not None else {os.getuid()})
        self.events = []
        self.rejected = 0
        self.lock = threading.Lock()
        super().__init__(str(socket_path), Handler)

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            # Linux kernel credentials on AF_UNIX; never trust a caller-supplied UID.
            if not hasattr(socket, 'SO_PEERCRED'):
                raise ValueError('peer credentials unsupported')
            raw = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
            peer_pid, peer_uid, peer_gid = struct.unpack('3i', raw)
            if peer_uid not in self.server.allowed_uids:
                raise ValueError('unauthorized peer')
            data = self.rfile.readline(4097)
            if not data.endswith(b"\n") or len(data) > 4096:
                raise ValueError("size or framing")
            event = json.loads(data)
            if (not isinstance(event, dict) or set(event) != ALLOWED
                or event["operation"] != "synthetic-effect"
                or not isinstance(event["case_id"], str)
                or len(event["case_id"]) > 128
                or not isinstance(event["challenge"], str)):
                raise ValueError("invalid event")
            if self.server.authority is not None:
                admitted = self.server.authority.consume(
                    case_id=event["case_id"], purpose=event["operation"],
                    token=event["challenge"])
            else:
                admitted = event["challenge"] == self.server.challenge
            if not admitted:
                raise ValueError("invalid event")
            with self.server.lock:
                if any(e["case_id"] == event["case_id"] for e in self.server.events):
                    raise ValueError("duplicate")
                if self.server.durable_events is not None:
                    self.server.durable_events.append(event["case_id"], event["operation"])
                self.server.events.append(event)
            self.wfile.write(b'{"status":"recorded"}\n')
        except (ValueError, UnicodeError, OSError, TimeoutError):
            with self.server.lock:
                self.server.rejected += 1

def serve(path, challenge, allowed_uids):
    location = pathlib.Path(path)
    if not location.parent.is_dir():
        raise RuntimeError("socket parent unavailable")
    if location.exists():
        raise RuntimeError("refusing existing socket path")
    server = Receiver(location, challenge, allowed_uids)
    os.chmod(location, 0o660)
    try:
        server.serve_forever()
    finally:
        server.server_close()

def main():
    # Fail closed without operator configured challenge and socket directory.
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    runtime_dir = os.environ.get("RUNTIME_DIRECTORY")
    if not credential_dir or not runtime_dir:
        raise SystemExit("observer requires systemd credential and runtime directories")
    try:
        challenge_file = pathlib.Path(credential_dir) / "observer_challenge"
        challenge = challenge_file.read_text(encoding="ascii").strip()
        allowed_uid = pwd.getpwnam("gts-broker").pw_uid
        runtime = pathlib.Path(runtime_dir).resolve(strict=True)
        if len(challenge) < 32 or not runtime.is_dir():
            raise ValueError("invalid challenge or runtime directory")
    except (OSError, KeyError, ValueError, UnicodeError) as exc:
        raise SystemExit("observer configuration unavailable") from exc
    # No trusted issuance channel exists yet; refusing the insecure legacy path.
    raise SystemExit("trusted challenge issuance not configured; refuse deployment")

if __name__ == "__main__":
    main()
