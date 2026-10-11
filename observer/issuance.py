"""Bounded local evaluator-to-observer challenge issuance endpoint.

Kernel peer UID authenticates the caller. This is a testable IPC primitive,
not an installed evaluator identity or secure broker-delivery mechanism.
"""
import json
import os
import socket
import socketserver
import struct
import threading

class IssuanceServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    def __init__(self, path, authority, evaluator_uid, observer_uid=None):
        if not isinstance(evaluator_uid, int) or evaluator_uid < 0:
            raise ValueError("invalid evaluator identity")
        if observer_uid is not None and evaluator_uid == observer_uid:
            raise ValueError("evaluator must be distinct from observer")
        self.authority = authority
        self.evaluator_uid = evaluator_uid
        self.lock = threading.Lock()
        super().__init__(str(path), IssuanceHandler)

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
