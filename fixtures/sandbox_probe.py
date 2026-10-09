"""Synthetic attack attempts inside a network-isolated mount namespace."""
import json
import pathlib
import socket

def probe():
    results = {}
    try:
        pathlib.Path("/tmp/sandbox-can-write").write_text("ok")
        results["scratch_writable"] = True
    except OSError:
        results["scratch_writable"] = False
    try:
        pathlib.Path("/probe.py").write_text("tamper")
        results["fixture_modified"] = True
    except OSError:
        results["fixture_modified"] = False
    results["host_home_visible"] = pathlib.Path("/home/triangulatorium").exists()
    try:
        socket.create_connection(("127.0.0.1", 9), timeout=0.3)
        results["network_connected"] = True
    except OSError:
        results["network_connected"] = False
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("127.0.0.1", 9))
        results["network_socket_usable"] = True
    except OSError:
        results["network_socket_usable"] = False
    return results

print(json.dumps(probe(), sort_keys=True))
