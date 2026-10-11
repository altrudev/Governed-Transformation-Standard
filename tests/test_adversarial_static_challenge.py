"""Red-team characterization: existing static challenge authorizes invented cases."""
import os
import tempfile
import threading
import unittest
from pathlib import Path
from broker.client import submit
from observer.service import Receiver
class StaticChallengeFinding(unittest.TestCase):
    def test_static_challenge_allows_unissued_different_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            server=Receiver(Path(tmp)/"s.sock","a"*32,{os.getuid()})
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            try:
                accepted=submit(server.server_address,{"case_id":"unissued-arbitrary-case",
                    "operation":"synthetic-effect","challenge":"a"*32})
                self.assertTrue(accepted)  # Characterizes vulnerability, NOT desired behavior.
                self.assertEqual(len(server.events),1)
            finally:
                server.shutdown();server.server_close();thread.join(timeout=3)
