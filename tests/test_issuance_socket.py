import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from observer.challenge_authority import ChallengeAuthority
from observer.issuance import IssuanceServer, request_challenge

class IssuanceSocketTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/"issuer.sock"
        self.authority=ChallengeAuthority()
        self.server=IssuanceServer(self.path,self.authority,os.getuid())
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()
    def test_world_traversable_parent_rejected(self):
        other=Path(self.tmp.name)/"public"
        other.mkdir(mode=0o755)
        other.chmod(0o755)
        with self.assertRaises(PermissionError):
            IssuanceServer(other/"issuer.sock",self.authority,os.getuid())
    def test_socket_owner_only(self):
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)
    def test_existing_socket_path_rejected(self):
        with self.assertRaises(ValueError):
            IssuanceServer(self.path,self.authority,os.getuid())
    def test_malformed_scope_rejected(self):
        import socket, json
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(str(self.path))
            client.sendall(json.dumps({"case_id":"case-A","purpose":"synthetic-effect",
                                      "ttl_seconds":301}).encode()+b"\n")
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(client.recv(512),b"")
        self.assertFalse(self.authority.consume(case_id="case-A",purpose="synthetic-effect",token="fake"))
    def test_issued_token_binds_case(self):
        token=request_challenge(self.path,"case-A")
        self.assertFalse(self.authority.consume(case_id="case-B",purpose="synthetic-effect",token=token))
        self.assertTrue(self.authority.consume(case_id="case-A",purpose="synthetic-effect",token=token))
        self.assertFalse(self.authority.consume(case_id="case-A",purpose="synthetic-effect",token=token))
    def test_wrong_peer_uid_rejected(self):
        self.server.evaluator_uid=os.getuid()+100000
        with self.assertRaises((ValueError, OSError)):
            request_challenge(self.path,"forbidden")
    def test_reused_case_rejected(self):
        request_challenge(self.path,"case-A")
        with self.assertRaises((ValueError, OSError)):
            request_challenge(self.path,"case-A")
    def test_evaluator_same_as_observer_rejected(self):
        with self.assertRaises(ValueError):
            IssuanceServer(Path(self.tmp.name)/"other.sock",self.authority,os.getuid(),observer_uid=os.getuid())
