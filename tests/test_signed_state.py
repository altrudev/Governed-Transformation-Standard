"""Signed-journal integrity and crash boundaries; unit test signer is NOT independent."""
import json
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from observer.signed_state import SignedDurableEvents, verify_checkpoint


class SignedStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.signer = Ed25519PrivateKey.generate()
        self.journal = self.root / "events.jsonl"
        self.signed = self.root / "state.json"

    def tearDown(self):
        self.temp.cleanup()

    def open(self):
        return SignedDurableEvents(self.journal, self.signed, self.signer)

    def test_signed_state_survives_restart(self):
        storage = self.open()
        self.assertEqual(storage.count, 0)
        storage.append("case-1", "synthetic-effect")
        packet = json.loads(self.signed.read_bytes())
        self.assertTrue(verify_checkpoint(
            packet, self.signer.public_key(), storage.journal.checkpoint()))
        restarted = self.open()
        self.assertEqual(restarted.count, 1)
        with self.assertRaises(ValueError):
            restarted.append("case-1", "synthetic-effect")
        restarted.append("case-2", "synthetic-effect")
        self.assertEqual(self.open().count, 2)

    def test_broker_cannot_forge_signed_checkpoint(self):
        storage = self.open()
        storage.append("c", "synthetic-effect")
        packet = json.loads(self.signed.read_bytes())
        packet["statement"]["entry_count"] = 0
        self.signed.write_text(json.dumps(packet))
        with self.assertRaises(ValueError):
            self.open()

    def test_key_substitution_fails(self):
        storage = self.open()
        storage.append("c", "synthetic-effect")
        other = Ed25519PrivateKey.generate()
        with self.assertRaises(ValueError):
            SignedDurableEvents(self.journal, self.signed, other)

    def test_truncation_mismatch_fails(self):
        storage = self.open()
        storage.append("c", "synthetic-effect")
        self.journal.write_bytes(b"")
        with self.assertRaises(ValueError):
            self.open()

    def test_crash_between_journal_and_signature_blocks_restart(self):
        storage = self.open()
        with patch.object(storage, "_publish", side_effect=OSError("simulated disk loss")):
            with self.assertRaises(OSError):
                storage.append("uncertain", "synthetic-effect")
        with self.assertRaises(RuntimeError):
            storage.append("new", "synthetic-effect")
        with self.assertRaises(ValueError):
            self.open()

    def test_missing_signature_for_nonempty_journal_denied(self):
        storage = self.open()
        storage.append("c", "synthetic-effect")
        self.signed.unlink()
        with self.assertRaises(ValueError):
            self.open()

    def test_permission_and_symlink_denials(self):
        storage = self.open()
        storage.append("c", "synthetic-effect")
        self.signed.chmod(0o644)
        with self.assertRaises(PermissionError):
            self.open()
        self.signed.chmod(0o600)
        self.signed.rename(self.root / "original")
        self.signed.symlink_to(self.root / "original")
        with self.assertRaises(PermissionError):
            self.open()

if __name__=="__main__":
    unittest.main()
