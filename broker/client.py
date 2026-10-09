"""Narrow observer submission broker client; never exposes observer query/signing."""
import json
import socket

def submit(path, event):
    if not isinstance(event, dict) or set(event) != {"case_id", "operation", "challenge"}:
        raise ValueError("unexpected broker message shape")
    if event["operation"] != "synthetic-effect":
        raise ValueError("unsupported operation")
    payload = json.dumps(event, separators=(",", ":")).encode() + b"\n"
    if len(payload) > 4096:
        raise ValueError("message too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        s.connect(path)
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        response = s.recv(256)
    if response != b'{"status":"recorded"}\n':
        raise PermissionError("observer did not accept effect")
    return True
