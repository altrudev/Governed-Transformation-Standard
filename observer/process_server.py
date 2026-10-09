"""Observer subprocess lifecycle with a private control pipe.

The untrusted fixture receives only the HTTP endpoint, not the control pipe.
This is OS-process separation, not OS-user or container isolation.
"""
import multiprocessing
from observer.fixture_server import FixtureServer

def serve(control):
    server = FixtureServer()
    try:
        port = server.start()
        control.send({"port": port, "observer_pid": __import__("os").getpid()})
        if control.poll(15) and control.recv() == "snapshot":
            control.send(server.observed())
    finally:
        server.close()
        control.close()

class ObserverProcess:
    def __init__(self):
        self.control, child = multiprocessing.Pipe()
        self.process = multiprocessing.Process(target=serve, args=(child,), daemon=True)
        self.process.start()
        child.close()
        if not self.control.poll(5):
            self.close()
            raise RuntimeError("observer startup timed out")
        info = self.control.recv()
        self.port = info["port"]
        self.pid = info["observer_pid"]

    def observed(self):
        self.control.send("snapshot")
        if not self.control.poll(5):
            raise RuntimeError("observer snapshot timed out")
        return self.control.recv()

    def close(self):
        if self.process.is_alive():
            self.process.join(timeout=1)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=3)
        self.control.close()
