"""Bounded local evaluator-to-observer challenge issuance endpoint.

Kernel peer UID authenticates the caller. This is a testable IPC primitive,
not an installed evaluator identity or secure broker-delivery mechanism.
"""
import json
import pathlib
import stat
import os
import socket
import socketserver
import struct
import threading

class IssuanceServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    def __init__(self, path, authority, evaluator_uid, observer_uid=None,
                 evaluator_gid=None):
        if not isinstance(evaluator_uid, int) or evaluator_uid < 0:
            raise ValueError("invalid evaluator identity")
        if observer_uid is not None and evaluator_uid == observer_uid:
            raise ValueError("evaluator must be distinct from observer")
        location = pathlib.Path(path)
        if not location.parent.is_dir() or location.is_symlink() or location.exists():
            raise ValueError("issuer socket location unavailable or already occupied")
        parent = location.parent.stat()
        if parent.st_uid != os.geteuid() or not stat.S_ISDIR(parent.st_mode):
            raise PermissionError("issuer socket parent must belong to observer")
        mode = stat.S_IMODE(parent.st_mode)
        if evaluator_gid is None:
            if mode & 0o077:
                raise PermissionError("issuer socket directory must be owner-private")
        else:
            # The operator provisions a separate directory owned by the
            # observer and grouped to the evaluator. Group can traverse only,
            # and never list or create files. Refuse broader permissions.
            if (not isinstance(evaluator_gid, int) or evaluator_gid < 0
                or evaluator_gid not in os.getgroups() + [os.getegid()]
                or parent.st_gid != evaluator_gid or mode != 0o710):
                raise PermissionError("issuer directory lacks isolated evaluator ACL")
        self.authority = authority
        self.evaluator_uid = evaluator_uid
        self.evaluator_gid = evaluator_gid
        self.lock = threading.Lock()
        super().__init__(str(path), IssuanceHandler)
        # The socket can be evaluator-group writable in group-isolated mode,
        # but never world-accessible; Linux SO_PEERCRED still binds the UID.
        try:
            if evaluator_gid is not None:
                os.chown(path, -1, evaluator_gid)
            os.chmod(path, 0o660 if evaluator_gid is not None else 0o600)
            st = pathlib.Path(path).lstat()
            if (not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.geteuid()
                or (evaluator_gid is not None and st.st_gid != evaluator_gid)):
                raise PermissionError("issuer socket ownership mismatch")
        except OSError:
            self.server_close()
            raise

class IssuanceHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            if not hasattr(socket, "SO_PEERCRED"):
                raise ValueError("no kernel peer credential support")
            raw = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                          struct.calcsize("3i"))
            _, uid, _ = struct.unpack("3i", raw)
            if uid != self.server.evaluator_uid:
                raise PermissionError("untrusted issuer")
            payload = self.rfile.readline(1025)
            if not payload.endswith(b"\n") or len(payload) > 1024:
                raise ValueError("framing")
            request = json.loads(payload)
            if (not isinstance(request, dict)
                or set(request) != {"case_id", "purpose", "ttl_seconds"}
                or request["purpose"] != "synthetic-effect"):
                raise ValueError("invalid request")
            # The evaluator must explicitly select scope; no general signing API.
            token = self.server.authority.issue(
                case_id=request["case_id"], purpose=request["purpose"],
                ttl_seconds=request["ttl_seconds"])
            self.wfile.write(json.dumps({"challenge":token}).encode("ascii")+b"\n")
        except (OSError, ValueError, TypeError, PermissionError, UnicodeError):
            return

def request_challenge(path, case_id, ttl_seconds=30):
    message = {"case_id":case_id,"purpose":"synthetic-effect","ttl_seconds":ttl_seconds}
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(path))
        client.sendall(json.dumps(message).encode()+b"\n")
        client.shutdown(socket.SHUT_WR)
        response = client.recv(1024)
    answer = json.loads(response)
    token = answer["challenge"]
    if not isinstance(token,str) or len(token)!=64:
        raise ValueError("untrusted issuer response")
    return token
