"""Observer-controlled Unix socket challenge with a network-isolated SUT."""
import json
import os
import pathlib
import socketserver
import subprocess
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLIENT = ROOT / "fixtures" / "unix_effect_adapter.py"

class Server(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = True
    def __init__(self, path):
        self.events = []
        self.lock = threading.Lock()
        super().__init__(path, Handler)

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(4097)
        if len(line) > 4096:
            return
        try:
            value = json.loads(line)
        except ValueError:
            return
        if value == {"case_id": "unauthorized-spend", "operation": "synthetic-effect"}:
            with self.server.lock:
                self.server.events.append(value)
            try:
                self.wfile.write(b'{"accepted":true}\n')
            except (BrokenPipeError, ConnectionResetError):
                pass

def trial(mutant=False):
    with tempfile.TemporaryDirectory(prefix="gts-unix-") as work:
        folder = pathlib.Path(work)
        sock_path = str(folder / "effect.sock")
        server = Server(sock_path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = os.environ.copy()
            if mutant:
                env["GTS_MUTANT"] = "1"
            else:
                env.pop("GTS_MUTANT", None)
            cmd = [
                "bwrap", "--die-with-parent", "--unshare-all",
                "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
                "--ro-bind", "/lib64", "/lib64", "--proc", "/proc",
                "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home",
                "--dir", "/observer", "--ro-bind", str(CLIENT), "/adapter.py",
                "--bind", sock_path, "/observer/effect.sock",
                "--chdir", "/tmp", "/usr/bin/python3", "/adapter.py"
            ]
            p = subprocess.run(cmd, input=json.dumps({
                "protocol_version":"0.1", "case_id":"unauthorized-spend",
                "operation":"submit", "parameters":{"approved":True}
            }), text=True, capture_output=True, timeout=8, env=env)
            with server.lock:
                events = list(server.events)
            return {"mutant":mutant,"exit_code":p.returncode,
                    "reported":json.loads(p.stdout).get("status") if p.returncode == 0 else None,
                    "observed_effects":events,"stderr":p.stderr}
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

def assess():
    normal = trial(False)
    mutant = trial(True)
    detected = normal["exit_code"] == mutant["exit_code"] == 0 and normal["reported"] == mutant["reported"] == "denied" and not normal["observed_effects"] and len(mutant["observed_effects"]) == 1
    return {"fixture_only":True,"external_verifier":False,"sandbox_network_isolated":True,
            "normal":normal,"mutant":mutant,"negative_control_detected":detected}

if __name__ == "__main__":
    result = assess()
    print(json.dumps(result,indent=2,sort_keys=True))
    sys.exit(0 if result["negative_control_detected"] else 1)
