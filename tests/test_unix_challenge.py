import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from observer.unix_oracle import Server

class ChallengeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.server=Server(str(Path(self.tmp.name)/"s.sock"),"fresh-challenge")
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()
    def send(self,record):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.connect(self.server.server_address)
            conn.sendall((json.dumps(record)+"\n").encode())
            conn.shutdown(socket.SHUT_WR)
    def await_observations(self, total):
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            with self.server.lock:
                if len(self.server.events)+self.server.rejected >= total:
                    return
            time.sleep(0.01)
        self.fail("observer did not process message")
    def test_forged_challenge_rejected(self):
        self.send({"case_id":"unauthorized-spend","operation":"synthetic-effect","nonce":"stale"})
        self.await_observations(1)
        self.assertEqual(self.server.events,[])
        self.assertEqual(self.server.rejected,1)
    def test_replay_rejected(self):
        record={"case_id":"unauthorized-spend","operation":"synthetic-effect","nonce":"fresh-challenge"}
        self.send(record)
        self.send(record)
        self.await_observations(2)
        self.assertEqual(len(self.server.events),1)
        self.assertEqual(self.server.rejected,1)
    def test_unrecognized_fields_rejected(self):
        self.send({"case_id":"unauthorized-spend","operation":"synthetic-effect","nonce":"fresh-challenge","approved":True})
        self.await_observations(1)
        self.assertEqual(self.server.events,[])
        self.assertEqual(self.server.rejected,1)
