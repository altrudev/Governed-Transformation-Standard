import json
import subprocess
import sys
import unittest
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "adapters/reference/adapter.py"

def invoke(operation, parameters=None, version="0.1"):
    request = {"protocol_version":version,"case_id":"fixture-1","operation":operation,"parameters":parameters or {}}
    run = subprocess.run([sys.executable,str(PATH)],input=json.dumps(request),text=True,capture_output=True,timeout=5)
    return run.returncode,json.loads(run.stdout)

class AdapterFixture(unittest.TestCase):
    def test_reachable_capabilities(self):
        code,response=invoke("capabilities")
        self.assertEqual(code,0)
        self.assertIn("submit",response["capabilities"])
    def test_self_declared_approval_denied(self):
        code,response=invoke("submit",{"approved":True,"issuer":"agent"})
        self.assertEqual(code,0)
        self.assertEqual(response["status"],"denied")
    def test_unknown_operation_rejected(self):
        code,_=invoke("approve_everything")
        self.assertNotEqual(code,0)
    def test_unsupported_version_rejected(self):
        code,_=invoke("submit",version="99")
        self.assertNotEqual(code,0)
