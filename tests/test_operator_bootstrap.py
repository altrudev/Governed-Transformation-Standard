"""Safety tests for privileged operator bootstrap without performing actions."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deployment import bootstrap_host as boot
from deployment import host_acceptance as acceptance


class OperatorBootstrapTests(unittest.TestCase):
    def test_bootstrap_defaults_to_read_only(self):
        p = Path(boot.__file__)
        result = subprocess.run(["python3", str(p)], capture_output=True,
                                text=True, check=True, timeout=6)
        self.assertIn("DRY RUN ONLY", result.stdout)

    def test_host_acceptance_defaults_to_read_only(self):
        p = Path(acceptance.__file__)
        result = subprocess.run(["python3", "-m", "deployment.host_acceptance"],
                                cwd=p.parents[1], capture_output=True,
                                text=True, check=True, timeout=6)
        self.assertIn("DRY RUN", result.stdout)

    def test_user_checkout_cannot_execute_privileged_bootstrap(self):
        with self.assertRaises(PermissionError):
            boot._require_root_copy()
        with self.assertRaises(PermissionError):
            boot.start_synthetic()

    def test_no_key_creation_outside_explicit_prepare(self):
        with patch.object(boot, "prepare") as prepare, patch.object(
                boot, "start_synthetic") as start:
            result = subprocess.run(["python3", str(Path(boot.__file__)),
                                     "--create-key"], capture_output=True,
                                    text=True, timeout=6)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires explicit --apply", result.stderr)
            prepare.assert_not_called()
            start.assert_not_called()

    def test_manifest_detects_modified_installed_source(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for pkg in ("observer", "broker", "evaluator", "deployment"):
                (root/pkg).mkdir()
            file = root/"observer"/"runtime.py"
            file.write_bytes(b"stable")
            manifest = {"schema":"gts.operator-source-bundle.v1",
                        "source_revision":"a"*40,
                        "entries":[{"path":"observer/runtime.py",
                                    "size":6,
                                    "sha256":hashlib.sha256(b"stable").hexdigest()}]}
            (root/"SOURCE-MANIFEST.json").write_text(json.dumps(manifest))
            with patch.object(boot, "INSTALL", root), patch.object(
                    boot, "protected", lambda _: None):
                self.assertEqual(boot.verify_installed_source(), "a"*40)
                file.write_bytes(b"tamper")
                with self.assertRaises(PermissionError):
                    boot.verify_installed_source()

    def test_unmanifested_module_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for pkg in ("observer", "broker", "evaluator", "deployment"):
                (root/pkg).mkdir()
            file=root/"observer"/"runtime.py"
            file.write_bytes(b"safe")
            digest=hashlib.sha256(b"safe").hexdigest()
            (root/"SOURCE-MANIFEST.json").write_text(
                json.dumps({"schema":"gts.operator-source-bundle.v1",
                            "source_revision":"b"*40,
                            "entries":[{"path":"observer/runtime.py","size":4,
                                        "sha256":digest}]}))
            (root/"observer"/"shadow.py").write_text("raise RuntimeError('hidden import')")
            with patch.object(boot,"INSTALL",root),patch.object(
                    boot,"protected",lambda _:None):
                with self.assertRaisesRegex(PermissionError,"unmanifested"):
                    boot.verify_installed_source()

if __name__ == "__main__":
    unittest.main()
