"""Evaluator-to-broker restricted Unix delivery of ONE scoped observer event.

Does not grant evaluator authority: issuance and operator provisioning must
establish that separately. Not an independent deployment qualification.
"""
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
import threading

from broker.client import submit

FIELDS = frozenset({"case_id", "operation", "challenge"})


def _validate(event):
    if not isinstance(event, dict) or set(event) != FIELDS:
        raise ValueError("invalid delivery envelope")
    case = event["case_id"]
    token = event["challenge"]
    if (not isinstance(case, str) or not 1 <= len(case) <= 128
            or event["operation"] != "synthetic-effect"
            or not isinstance(token, str) or len(token) != 64
            or any(c not in "0123456789abcdef" for c in token)):
        raise ValueError("unscoped event")
    return event


class DeliveryServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path, observer_socket, *, evaluator_uid,
                 broker_uid=None, evaluator_gid=None, require_distinct=True,
                 durable_attempts=None):
        if (not isinstance(evaluator_uid, int) or evaluator_uid < 0
                or broker_uid is not None and broker_uid != os.geteuid()):
            raise ValueError("invalid broker or evaluator identity")
        if require_distinct and (broker_uid is None or evaluator_uid == broker_uid):
            raise ValueError("the evaluator and broker identities must be distinct")
        if require_distinct and durable_attempts is None:
            raise ValueError("production broker requires durable reservation state")
        path = Path(path)
        if not path.parent.is_dir() or path.is_symlink() or path.exists():
            raise ValueError("delivery socket path unavailable")
        parent = path.parent.stat()
        if parent.st_uid != os.geteuid() or not stat.S_ISDIR(parent.st_mode):
            raise PermissionError("broker must own delivery parent")
        mode = stat.S_IMODE(parent.st_mode)
        if evaluator_gid is None:
            if mode & 0o077:
                raise PermissionError("broker delivery parent must be owner-private")
        else:
            if (not isinstance(evaluator_gid, int) or evaluator_gid < 0
                    or parent.st_gid != evaluator_gid or mode != 0o710
                    or evaluator_gid not in os.getgroups() + [os.getegid()]):
                raise PermissionError("delivery parent lacks restricted evaluator group")
        self.observer_socket = str(observer_socket)
        self.evaluator_uid = evaluator_uid
        self.evaluator_gid = evaluator_gid
        self._attempted = set()
        self._lock = threading.Lock()
        self.durable_attempts = durable_attempts
        super().__init__(str(path), Handler)
        try:
            if evaluator_gid is not None:
                os.chown(path, -1, evaluator_gid)
            os.chmod(path, 0o660 if evaluator_gid is not None else 0o600)
            actual = path.lstat()
            if (not stat.S_ISSOCK(actual.st_mode) or actual.st_uid != os.geteuid()
                    or evaluator_gid is not None and actual.st_gid != evaluator_gid):
                raise PermissionError("delivery socket custody mismatch")
        except OSError:
            self.server_close()
            raise


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            if not hasattr(socket, "SO_PEERCRED"):
                raise ValueError("peer credentials unavailable")
            raw = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                          struct.calcsize("3i"))
            _, peer_uid, _ = struct.unpack("3i", raw)
            if peer_uid != self.server.evaluator_uid:
                raise PermissionError("unauthorized evaluator")
            payload = self.rfile.readline(1025)
            if not payload.endswith(b"\n") or len(payload) > 1024:
                raise ValueError("invalid framing")
            event = _validate(json.loads(payload))
            case = event["case_id"]
            # Reserve BEFORE forwarding. Any ambiguous acknowledgement is
            # IN_DOUBT, never safe for blind retry or duplicate effect.
            with self.server._lock:
                if self.server.durable_attempts is not None:
                    if not self.server.durable_attempts.reserve(case):
                        raise ValueError("duplicate, ambiguous or unavailable durable reservation")
                else:
                    if case in self.server._attempted:
                        raise ValueError("duplicate or ambiguous delivery")
                    self.server._attempted.add(case)
            if not submit(self.server.observer_socket, event):
                raise PermissionError("observer rejected delivery")
            if (self.server.durable_attempts is not None
                    and not self.server.durable_attempts.acknowledge(case)):
                raise PermissionError("observer accepted but broker record is in doubt")
            self.wfile.write(b'{"status":"recorded"}\n')
        except (OSError, ValueError, TypeError, UnicodeError, PermissionError):
            return


def deliver(path, event):
    event = _validate(event)
    payload = json.dumps(event, separators=(",", ":")).encode("ascii") + b"\n"
    if len(payload) > 1024:
        raise ValueError("delivery exceeds bounded frame")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(str(path))
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            response = client.recv(256)
    except OSError as exc:
        raise PermissionError("broker denied or unavailable") from exc
    if response != b'{"status":"recorded"}\n':
        raise PermissionError("broker did not verify delivery")
    return True
