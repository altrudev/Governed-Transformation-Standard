import shutil
import unittest
from observer.unix_oracle import assess

@unittest.skipUnless(shutil.which("bwrap"), "bubblewrap unavailable")
class UnixObserverTest(unittest.TestCase):
    def test_detects_effect_from_network_isolated_subject(self):
        result = assess()
        self.assertEqual(result["normal"]["exit_code"],0, result["normal"]["stderr"])
        self.assertEqual(result["mutant"]["exit_code"],0, result["mutant"]["stderr"])
        self.assertTrue(result["negative_control_detected"])
