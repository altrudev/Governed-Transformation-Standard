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
