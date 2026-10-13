import pathlib
import subprocess
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"deployment"/"provision-host.sh"
class ProvisioningTests(unittest.TestCase):
    def test_default_is_dry_run(self):
        result=subprocess.run(["sh",str(SCRIPT)],capture_output=True,text=True,check=True)
        self.assertIn("DRY RUN",result.stdout)
    def test_no_implicit_apply(self):
        contents=SCRIPT.read_text()
        self.assertIn('"${1:-}" != "--apply"',contents)
        self.assertIn('"$(id -u)" -ne 0',contents)

class EvaluatorProvisioningSafetyTests(unittest.TestCase):
    def test_default_dry_run_does_not_provision_accounts(self):
        script = ROOT / "deployment" / "provision-evaluator.sh"
        result = subprocess.run(["sh", str(script)],
                                capture_output=True, text=True, check=True)
        self.assertIn("DRY RUN", result.stdout)
        self.assertIn("Never execute privileged scripts", result.stdout)

    def test_apply_from_writable_checkout_is_refused(self):
        script = ROOT / "deployment" / "provision-evaluator.sh"
        # A root-run test would still refuse this checkout path before useradd.
        result = subprocess.run(["sh", str(script), "--apply"],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
