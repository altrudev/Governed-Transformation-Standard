"""Operator bundle gate: deterministic packaging and refusal of unreviewed trees."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from deployment.package_release import build


def run(*args):
    return subprocess.run(list(args), check=True, capture_output=True, timeout=9)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        run("git", "init", "-q", str(self.root))
        for sub in ("observer", "broker", "evaluator", "deployment"):
            (self.root / sub).mkdir()
            (self.root / sub / "__init__.py").write_text("")
        for path in ("deployment/bootstrap_host.py", "deployment/gts-observer.service",
                     "deployment/gts-broker.service",
                     "deployment/gts-sockets.tmpfiles.conf",
                     "observer/runtime.py", "broker/runtime.py",
                     "evaluator/synthetic_acceptance.py"):
            (self.root / path).write_text("reviewed = True\n")
        (self.root / "observer" / "malicious-link.py").symlink_to("/etc/passwd")
        run("git", "-C", str(self.root), "add", ".")
        run("git", "-C", str(self.root), "-c", "user.name=Test",
            "-c", "user.email=test@example.invalid", "commit", "-qm", "snapshot")

    def tearDown(self):
        self.temp.cleanup()

    def test_rejects_symlinked_runtime_content(self):
        with self.assertRaisesRegex(ValueError, "disallowed tracked type"):
            build(self.root, self.root.parent / "candidate.tar.gz")

    def test_clean_deterministic_bundle_has_only_approved_regular_files(self):
        run("git", "-C", str(self.root), "rm", "-q", "observer/malicious-link.py")
        run("git", "-C", str(self.root), "-c", "user.name=Test",
            "-c", "user.email=test@example.invalid", "commit", "-qm", "remove link")
        one=self.root.parent / "first.tar.gz"
        two=self.root.parent / "second.tar.gz"
        first=build(self.root, one)
        second=build(self.root, two)
        self.assertEqual(first["sha256"], second["sha256"])
        with tarfile.open(one, "r:gz") as archive:
            names=archive.getnames()
            self.assertIn("SOURCE-MANIFEST.json",names)
            self.assertIn("deployment/bootstrap_host.py",names)
            self.assertTrue(all(f.isfile() for f in archive.getmembers()))
            payload=json.load(archive.extractfile("SOURCE-MANIFEST.json"))
            self.assertEqual(payload["source_revision"],first["revision"])
            self.assertEqual(payload["qualification"],"UNSIGNED_SOURCE_INTAKE")

    def test_refuses_dirty_uncommitted_source(self):
        (self.root / "observer/runtime.py").write_text("changed = True\n")
        with self.assertRaisesRegex(RuntimeError, "dirty release source"):
            build(self.root, self.root.parent / "candidate.tar.gz")


if __name__=="__main__":
    unittest.main()
