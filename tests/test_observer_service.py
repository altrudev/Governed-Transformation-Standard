import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from observer.service import Receiver

class ServiceProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = Receiver(Path(self.tmp.name)/"s.sock", "challenge-"+"a"*32)
        self.thread = threading.Thread(target=self.s.serve_forever, daemon=True)
        self.thread.start()
    def tearDown(self):
        self.s.shutdown()
        self.s.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()
    def send(self, value):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect(self.s.server_address)
            sock.sendall(json.dumps(value).encode()+b"\n")
            sock.shutdown(socket.SHUT_WR)
            return sock.makefile("rb").read()
    def event(self):
        return {"case_id":"x","operation":"synthetic-effect","challenge":"challenge-"+"a"*32}
    def test_valid_event_recorded(self):
        self.assertIn(b"recorded",self.send(self.event()))
        self.assertEqual(len(self.s.events),1)
    def test_replay_rejected(self):
        self.send(self.event())
        self.assertEqual(self.send(self.event()),b"")
        self.assertEqual(len(self.s.events),1)
    def test_wrong_challenge_rejected(self):
        e=self.event();e["challenge"]="bad"
        self.assertEqual(self.send(e),b"")
        self.assertEqual(self.s.events,[])
    def test_arbitrary_command_rejected(self):
        e=self.event();e["operation"]="sign-arbitrary-data"
        self.assertEqual(self.send(e),b"")
        self.assertEqual(self.s.events,[])
    def test_extra_fields_rejected(self):
        e=self.event();e["path"]="/etc/shadow"
        self.assertEqual(self.send(e),b"")
    def test_missing_configuration_fails_closed(self):
        from unittest.mock import patch
        from observer.service import main
        with patch.dict("os.environ",{},clear=True):
            with self.assertRaises(SystemExit):
                main()
