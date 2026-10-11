import os
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
