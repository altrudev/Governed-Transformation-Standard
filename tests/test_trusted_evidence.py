import base64
import copy
import hashlib
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from observer.evidence import canonical, produce
from observer.trusted_evidence import verify

class TrustedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.owner = Ed25519PrivateKey.generate()
        self.attacker = Ed25519PrivateKey.generate()
        self.trust = self.owner.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.digest = "ab" * 32
        self.challenge = "verifier-issued-nonce"
        self.report = {"subject_sha256":self.digest, "challenge":self.challenge,
                       "observed_effects":[{"event":"synthetic"}]}
    def packet(self, key):
        raw = canonical(self.report)
        return {"alg":"Ed25519", "report":copy.deepcopy(self.report),
                "sha256":hashlib.sha256(raw).hexdigest(),
                "signature":base64.b64encode(key.sign(raw)).decode(),
                "public_key":base64.b64encode(key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()}
    def test_pinned_verifier_accepts_expected_key(self):
        self.assertTrue(verify(self.packet(self.owner),self.trust,self.digest,self.challenge))
    def test_attacker_cannot_substitute_key_and_resign(self):
        self.assertFalse(verify(self.packet(self.attacker),self.trust,self.digest,self.challenge))
    def test_wrong_challenge_rejected(self):
        self.assertFalse(verify(self.packet(self.owner),self.trust,self.digest,"different"))
    def test_subject_replacement_rejected(self):
        self.assertFalse(verify(self.packet(self.owner),self.trust,"00"*32,self.challenge))
    def test_changed_observation_rejected(self):
        packet=self.packet(self.owner)
        packet["report"]["observed_effects"]=[]
        self.assertFalse(verify(packet,self.trust,self.digest,self.challenge))
    def test_self_signed_fixture_not_trusted(self):
        self.assertFalse(verify(produce(self.report),self.trust,self.digest,self.challenge))
    def test_missing_anchor_rejected(self):
        self.assertFalse(verify(self.packet(self.owner),None,self.digest,self.challenge))
