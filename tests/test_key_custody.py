import os
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from observer.key_custody import load_observer_signer

class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/"key.pem"
        key=Ed25519PrivateKey.generate()
        self.path.write_bytes(key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
        self.path.chmod(0o600)
    def tearDown(self):
        self.tmp.cleanup()
    def test_owner_only_ed25519_load(self):
        signer=load_observer_signer(self.path)
        self.assertEqual(len(signer.sign(b"test")),64)
    def test_broad_access_rejected(self):
        self.path.chmod(0o640)
        with self.assertRaises(PermissionError):
            load_observer_signer(self.path)
    def test_symlink_rejected(self):
        link=Path(self.tmp.name)/"link"
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            load_observer_signer(link)
    def test_hardlink_rejected(self):
        link=Path(self.tmp.name)/"hardlink"
        os.link(self.path,link)
        with self.assertRaises(PermissionError):
            load_observer_signer(self.path)
