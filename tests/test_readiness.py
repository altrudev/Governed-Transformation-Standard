import unittest
from deployment.readiness import inspect

class ReadinessTests(unittest.TestCase):
    def test_gate_requires_every_prerequisite(self):
        result = inspect()
        self.assertEqual(result["ready_for_operator_deployment_review"], all(result["checks"].values()))
    def test_gate_does_not_read_secrets_or_modify_host(self):
        result = inspect()
        self.assertIs(result["credential_contents_accessed"], False)
        self.assertIs(result["changes_made"], False)
