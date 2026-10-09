import copy
import unittest
from observer.evidence import produce, validate

class EvidenceTests(unittest.TestCase):
    def test_valid_signature(self):
        self.assertTrue(validate(produce({"trial":"fixture","detected":True})))
    def test_tampered_verdict_rejected(self):
        signed=produce({"trial":"fixture","detected":True})
        tampered=copy.deepcopy(signed)
        tampered["report"]["detected"]=False
        self.assertFalse(validate(tampered))
    def test_tampered_signature_rejected(self):
        signed=produce({"trial":"fixture"})
        signed["signature"]="AAAA"
        self.assertFalse(validate(signed))
    def test_self_signed_not_independent(self):
        signed=produce({"trial":"fixture"})
        self.assertEqual(signed["key_provenance"],"ephemeral-runner-self-generated")
        self.assertFalse(signed["independent_verification"])
