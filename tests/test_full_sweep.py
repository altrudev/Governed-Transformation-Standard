import tempfile
import unittest
from pathlib import Path
from shutil import copytree
from assurance.full_sweep import ROOT, run

class FullSweepTests(unittest.TestCase):
    def test_current_release_controls_fail_gate(self):
        result=run()
        self.assertEqual(result["overall"],"BLOCKED")
        by_id={x["id"]:x["status"] for x in result["findings"]}
        self.assertEqual(by_id["challenge_authority_enforced_in_receiver"],"STATIC_INDICATOR_ONLY")
        self.assertEqual(by_id["journal_write_on_observation"],"BLOCKED")
    def test_a_comment_does_not_satisfy_call_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            for part in ("observer","deployment"):
                copytree(ROOT/part,base/part,ignore=lambda d,n: ["__pycache__"])
            (base/"observer/service.py").write_text((base/"observer/service.py").read_text()
                 +"\n# consume sign_journal fsync\n")
            self.assertEqual(run(base)["overall"],"BLOCKED")
    def test_gate_count_matches_findings(self):
        result=run()
        self.assertEqual(result["total_gates"],len(result["findings"]))
        self.assertEqual(result["verified_gates"],0)
        self.assertEqual(result["static_indicators_found"],sum(f["status"]=="STATIC_INDICATOR_ONLY" for f in result["findings"]))
