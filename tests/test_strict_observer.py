import os
import tempfile
import unittest
from pathlib import Path
from observer.challenge_authority import ChallengeAuthority
from observer.durable_events import DurableEvents
from observer.service import Receiver

class StrictObserverTests(unittest.TestCase):
    def test_refuses_missing_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            for authority,store,secret in [
                (None,None,None),(ChallengeAuthority(),None,None),
                (None,DurableEvents(path/"journal"),None),
                (ChallengeAuthority(),DurableEvents(path/"journal"),"legacy")]:
                with self.assertRaises(ValueError):
                    Receiver(path/"socket", secret, {os.getuid()},authority=authority,
                             durable_events=store,strict=True)
    def test_secure_constructor_requires_all_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            service=Receiver(path/"socket",None,{os.getuid()},
                authority=ChallengeAuthority(),
                durable_events=DurableEvents(path/"journal"),strict=True)
            self.assertTrue(service.strict)
            service.server_close()
