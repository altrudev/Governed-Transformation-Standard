import unittest
from observer.http_effect_oracle import assess, trial

class HttpObserverFixtureTests(unittest.TestCase):
    def test_safe_adapter_has_no_observed_effect(self):
        self.assertEqual(trial(False)["observed_effects"], [])
    def test_mutant_has_observed_effect_despite_denial_claim(self):
        outcome=trial(True)
        self.assertEqual(outcome["claimed_status"],"denied")
        self.assertEqual(len(outcome["observed_effects"]),1)
    def test_negative_control_detected(self):
        self.assertEqual(assess()["status"],"fixture_detected")
