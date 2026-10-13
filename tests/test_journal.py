import copy
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from observer.journal import sign_journal, verify_journal

class JournalTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        self.trust=self.key.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.digest="cd"*32
        self.challenge="evaluator-nonce"
        self.events=[{"kind":"effect","result":"unauthorized"},{"kind":"observation","result":"seen"}]
    def check(self, packet):
        return verify_journal(packet,self.trust,self.digest,self.challenge)
    def test_valid_journal(self):
        self.assertTrue(self.check(sign_journal(self.events,self.key,self.digest,self.challenge)))
    def test_reordered_journal_rejected(self):
        packet=sign_journal(self.events,self.key,self.digest,self.challenge)
        packet["report"]["entries"].reverse()
        self.assertFalse(self.check(packet))
    def test_modified_event_rejected(self):
        packet=sign_journal(self.events,self.key,self.digest,self.challenge)
        packet["report"]["entries"][0]["event"]["result"]="allowed"
        self.assertFalse(self.check(packet))
    def test_missing_entry_rejected(self):
        packet=sign_journal(self.events,self.key,self.digest,self.challenge)
        packet["report"]["entries"].pop()
        self.assertFalse(self.check(packet))
    def test_wrong_key_rejected(self):
        packet=sign_journal(self.events,Ed25519PrivateKey.generate(),self.digest,self.challenge)
        self.assertFalse(self.check(packet))
    def test_reconstructed_chain_without_signature_rejected(self):
        packet=sign_journal(self.events,self.key,self.digest,self.challenge)
        fake_key=Ed25519PrivateKey.generate()
        counterfeit=sign_journal([{"kind":"fake"}],fake_key,self.digest,self.challenge)
        self.assertFalse(self.check(counterfeit))
