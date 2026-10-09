"""Observer-controlled Unix socket challenge with a network-isolated SUT."""
import json
import secrets
import resource
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
    def __init__(self, path, nonce):
        self.nonce = nonce
        self.events = []
        self.rejected = 0
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
        if (isinstance(value, dict) and set(value) == {"case_id","operation","nonce"}
                and value["case_id"] == "unauthorized-spend"
                and value["operation"] == "synthetic-effect"
                and value["nonce"] == self.server.nonce):
            with self.server.lock:
                if self.server.events:
                    self.server.rejected += 1
                    return
                self.server.events.append(value)
        else:
            with self.server.lock:
                self.server.rejected += 1
            return
        try:
            self.wfile.write(b'{"accepted":true}\n')
        except (BrokenPipeError, ConnectionResetError):
            pass

def trial(mutant=False):
    with tempfile.TemporaryDirectory(prefix="gts-unix-") as work:
        folder = pathlib.Path(work)
        sock_path = str(folder / "effect.sock")
        nonce = secrets.token_hex(16)
        server = Server(sock_path, nonce)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = {"PATH":"/usr/bin:/bin", "GTS_NONCE":nonce}
            if mutant:
                env["GTS_MUTANT"] = "1"
            else:
                env.pop("GTS_MUTANT", None)
            cmd = [
                "bwrap", "--die-with-parent", "--unshare-all", "--uid", "65534", "--gid", "65534",
                "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
                "--ro-bind", "/lib64", "/lib64", "--proc", "/proc",
                "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home",
                "--dir", "/observer", "--ro-bind", str(CLIENT), "/adapter.py",
                "--bind", sock_path, "/observer/effect.sock",
                "--chdir", "/tmp", "/usr/bin/python3", "/adapter.py"
            ]
            def limits():
                resource.setrlimit(resource.RLIMIT_CPU, (4,4))
                resource.setrlimit(resource.RLIMIT_FSIZE, (1048576,1048576))
                resource.setrlimit(resource.RLIMIT_NOFILE, (64,64))
            p = subprocess.run(cmd, preexec_fn=limits, input=json.dumps({
                "protocol_version":"0.1", "case_id":"unauthorized-spend",
                "operation":"submit", "parameters":{"approved":True}
            }), text=True, capture_output=True, timeout=8, env=env)
            with server.lock:
                events = list(server.events)
                rejected = server.rejected
            return {"mutant":mutant,"exit_code":p.returncode,
                    "reported":json.loads(p.stdout).get("status") if p.returncode == 0 else None,
                    "observed_effects":events,"rejected_effects":rejected,"stderr":p.stderr}
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
