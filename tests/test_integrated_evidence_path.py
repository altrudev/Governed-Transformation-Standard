"""In-process end-to-end fixture; deliberately NOT independent host custody."""
import copy
import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from broker.client import submit
from observer.challenge_authority import ChallengeAuthority
from observer.durable_events import DurableEvents
from observer.journal import sign_journal, verify_journal
from observer.service import Receiver

class IntegratedFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)
        self.authority = ChallengeAuthority()
        self.store = DurableEvents(self.dir / "journal.jsonl")
        self.receiver = Receiver(self.dir / "receiver.sock", None, {os.getuid()},
                                 authority=self.authority, durable_events=self.store)
        self.thread = threading.Thread(target=self.receiver.serve_forever, daemon=True)
        self.thread.start()
        self.signer = Ed25519PrivateKey.generate()
        self.pinned = self.signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.subject = hashlib.sha256(b"fixture-subject").hexdigest()
        self.verifier_nonce = "verifier-issued-fixture-nonce"
    def tearDown(self):
        self.receiver.shutdown()
        self.receiver.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()
    def submit(self, case, token):
        return submit(self.receiver.server_address, {
            "case_id": case, "operation": "synthetic-effect", "challenge": token})
    def packet(self):
        recovered = DurableEvents(self.dir / "journal.jsonl")
        self.assertEqual(recovered.count, self.store.count)
        return sign_journal(self.receiver.events, self.signer,
                            self.subject, self.verifier_nonce)
    def verified(self, packet, pinned=None):
        return verify_journal(packet, pinned if pinned is not None else self.pinned,
                              self.subject, self.verifier_nonce)
    def test_full_fixture_and_control_removal(self):
        token = self.authority.issue(case_id="authorized")
        self.assertTrue(self.submit("authorized", token))
        packet = self.packet()
        self.assertTrue(self.verified(packet))
        with self.assertRaises(PermissionError):
            self.submit("authorized", token)
        with self.assertRaises(PermissionError):
            self.submit("unissued", "fake")
        wrong = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.assertFalse(self.verified(packet, wrong))
        corrupted = copy.deepcopy(packet)
        corrupted["report"]["entries"][0]["event"]["case_id"] = "forged"
        self.assertFalse(self.verified(corrupted))
        self.assertFalse(verify_journal(packet, self.pinned,
                         hashlib.sha256(b"wrong-subject").hexdigest(), self.verifier_nonce))
        self.assertFalse(verify_journal(packet, self.pinned, self.subject, "wrong-nonce"))
    def test_missing_journal_fails_recovery(self):
        self.submit("case", self.authority.issue(case_id="case"))
        self.packet()
        self.store.path.write_bytes(b"partial-tail")
        with self.assertRaises(ValueError):
            DurableEvents(self.store.path)
    def test_authority_not_issued_is_denied(self):
        with self.assertRaises(PermissionError):
            self.submit("unknown", "unknown")
        self.assertEqual(self.store.count, 0)
