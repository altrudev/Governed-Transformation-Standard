import unittest
from deployment.acceptance import evaluate, REQUIRED

class AcceptanceGateTests(unittest.TestCase):
    def test_never_accepts_unverified_claims(self):
        claims={key:True for key in REQUIRED}
        result=evaluate(claims)
        self.assertFalse(result["install_authorized"])
        self.assertTrue(result["requested_evidence_ignored"])
    def test_default_blocks_install(self):
        self.assertFalse(evaluate()["install_authorized"])
