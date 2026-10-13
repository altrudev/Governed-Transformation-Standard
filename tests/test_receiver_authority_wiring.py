import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from observer.challenge_authority import ChallengeAuthority
from observer.service import Receiver
from observer.durable_events import DurableEvents
from broker.client import submit

class ReceiverAuthorityWiring(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.auth=ChallengeAuthority()
        self.store=DurableEvents(Path(self.temp.name)/"journal.jsonl")
        self.receiver=Receiver(Path(self.temp.name)/"socket","LEGACY", {os.getuid()}, authority=self.auth, durable_events=self.store)
        self.worker=threading.Thread(target=self.receiver.serve_forever,daemon=True)
        self.worker.start()
    def tearDown(self):
        self.receiver.shutdown()
        self.receiver.server_close()
        self.worker.join(timeout=3)
        self.temp.cleanup()
    def request(self, case, token):
        return submit(self.receiver.server_address,{"case_id":case,"operation":"synthetic-effect","challenge":token})
    def test_issued_case_accepted_once(self):
        token=self.auth.issue(case_id="case1")
        self.assertTrue(self.request("case1",token))
        with self.assertRaises(PermissionError):self.request("case1",token)
    def test_legacy_secret_no_longer_authorizes_new_case(self):
        with self.assertRaises(PermissionError):self.request("invented","LEGACY")
        self.assertEqual(self.receiver.events,[])
    def test_token_substitution_rejected(self):
        token=self.auth.issue(case_id="first")
        with self.assertRaises(PermissionError):self.request("second",token)
        self.assertEqual(self.receiver.events,[])
    def test_failed_attempt_preserves_valid_token(self):
        token=self.auth.issue(case_id="first")
        with self.assertRaises(PermissionError):self.request("first","wrong")
        self.assertTrue(self.request("first",token))

    def test_ack_requires_persisted_event(self):
        token=self.auth.issue(case_id="durable")
        self.assertTrue(self.request("durable",token))
        reopened=DurableEvents(Path(self.temp.name)/"journal.jsonl")
        self.assertEqual(reopened.count,1)

    def test_persistence_exception_prevents_success(self):
        token=self.auth.issue(case_id="broken")
        def broken(*args):
            raise OSError("injected fsync or storage failure")
        self.store.append=broken
        with self.assertRaises(PermissionError):
            self.request("broken",token)
        self.assertEqual(self.receiver.events,[])
