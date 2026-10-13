import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/run-with-disk-tmp.sh"
class DiskTmpTests(unittest.TestCase):
    def test_private_disk_backed_tmp(self):
        with tempfile.TemporaryDirectory() as base:
            env={**os.environ,"XDG_STATE_HOME":base}
            result=subprocess.run(["sh",str(SCRIPT),sys.executable,"-c",
                "import tempfile,os,pathlib; p=pathlib.Path(tempfile.mkstemp()[1]); print(str(p)); print(oct(p.stat().st_mode & 0o777)); p.unlink()"],
                capture_output=True,text=True,env=env,check=True)
            lines=result.stdout.splitlines()
            self.assertTrue(lines[0].startswith(base))
            self.assertEqual(lines[1],"0o600")
            self.assertEqual((pathlib.Path(base)/"altru/tmp").stat().st_mode & 0o777,0o700)
    def test_missing_command_fails(self):
        result=subprocess.run(["sh",str(SCRIPT)],capture_output=True)
        self.assertEqual(result.returncode,64)
