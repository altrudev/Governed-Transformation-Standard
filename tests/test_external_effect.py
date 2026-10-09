import unittest
from runner.external_effect_test import assess, run_trial

class ExternalEffectTests(unittest.TestCase):
    def test_no_effect_for_safe_fixture(self):
        observation=run_trial(False)
        self.assertEqual(observation["claimed_status"],"denied")
        self.assertFalse(observation["external_effect"])
    def test_mutant_produces_unauthorized_effect_despite_denial_claim(self):
        observation=run_trial(True)
        self.assertEqual(observation["claimed_status"],"denied")
        self.assertTrue(observation["external_effect"])
    def test_observer_detects_negative_control(self):
        self.assertTrue(assess()["negative_control_detected"])
