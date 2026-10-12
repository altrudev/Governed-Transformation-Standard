import base64
import hashlib
import unittest
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from assurance.witness import canonical, verify_witness, SCHEMA
class ExternalWitnessTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        self.pub=self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.evidence=b"independent host log test fixture"
        self.rev="a"*40
        self.when=datetime.now(timezone.utc)
        self.statement={"schema":SCHEMA,"requirement":"real_cross_account_socket",
                        "revision":self.rev,"observed_at":self.when.isoformat(),
                        "outcome":"PASS","evidence_sha256":hashlib.sha256(self.evidence).hexdigest(),
                        "environment":"test host", "witness_id":"test-only-independent-witness"}
    def packet(self):
        return {"statement":dict(self.statement),
                "signature":base64.b64encode(self.key.sign(canonical(self.statement))).decode()}
    def check(self, packet=None, **kwargs):
        return verify_witness(packet or self.packet(), requirement=kwargs.get("requirement","real_cross_account_socket"),
            revision=kwargs.get("revision",self.rev),public_key=kwargs.get("public_key",self.pub),
            evidence_bytes=kwargs.get("evidence",self.evidence),now=kwargs.get("now",self.when))
    def test_signed_fixture(self):self.assertTrue(self.check())
    def test_wrong_key(self):
        other=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.assertFalse(self.check(public_key=other))
    def test_substituted_requirement(self):self.assertFalse(self.check(requirement="observer_owned_signer_and_pinned_verifier"))
    def test_substituted_commit(self):self.assertFalse(self.check(revision="b"*40))
    def test_mutated_evidence(self):self.assertFalse(self.check(evidence=b"forged"))
    def test_stale(self):self.assertFalse(self.check(now=self.when+timedelta(days=2)))
    def test_future(self):self.assertFalse(self.check(now=self.when-timedelta(minutes=6)))
    def test_forged_pass(self):
        statement=self.packet()
        statement["statement"]["outcome"]="FAIL"
        self.assertFalse(self.check(statement))
    def test_untrusted_extra_field(self):
        statement=self.packet()
        statement["statement"]["self_verified"]=True
        self.assertFalse(self.check(statement))
    def test_malformed_signature(self):
        statement=self.packet()
        statement["signature"]="!"
        self.assertFalse(self.check(statement))
