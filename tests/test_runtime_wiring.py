"""Production constructors must reject non-provisioned Linux identities.

These tests are developer-host rejection tests, NOT actual cross-account
acceptance tests for separately provisioned Linux service users.
"""
import os
import stat
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from observer import runtime as observer_runtime
from broker import runtime as broker_runtime


class RuntimeWiringTests(unittest.TestCase):
    def test_observer_rejects_unprovisioned_evaluator(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises((KeyError, PermissionError)):
                observer_runtime.preflight(
                    issuer_dir=Path(td)/"issuer",
                    observer_dir=Path(td)/"observer",
                    state_dir=Path(td)/"state")

    def test_broker_rejects_unprovisioned_evaluator(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises((KeyError, PermissionError)):
                broker_runtime.preflight(
                    delivery_dir=Path(td)/"delivery",
                    state_dir=Path(td)/"state")

    def test_observer_runtime_never_uses_legacy_static_secret_path(self):
        source = Path(observer_runtime.__file__).read_text()
        self.assertIn("SignedDurableEvents(",source)
        self.assertIn("strict=True",source)
        self.assertIn("load_observer_signer(",source)
        self.assertNotIn("observer_challenge",source)

    def test_broker_runtime_enforces_persistent_reservation(self):
        source = Path(broker_runtime.__file__).read_text()
        self.assertIn("DurableAttempts(",source)
        self.assertIn("durable_attempts=state",source)
        self.assertNotIn("require_distinct=False",source)

    def test_wrong_provisioned_socket_custody_fails(self):
        class User:
            def __init__(self,uid):self.pw_uid=uid
        class Group:
            def __init__(self,gid):self.gr_gid=gid
        actual=os.geteuid()
        # Pretend identities are distinct but never change OS UID; verify
        # that an actual process with the wrong UID is rejected.
        ids={"gts-observer":User(actual+200),"gts-broker":User(actual+201),
             "gts-evaluator":User(actual+202)}
        groups={"gts-observer":Group(os.getegid()),"gts-broker":Group(os.getegid()),
                "gts-evaluator":Group(os.getegid())}
        with tempfile.TemporaryDirectory() as td, patch.object(
            observer_runtime.pwd,"getpwnam",side_effect=lambda name:ids[name]), patch.object(
            observer_runtime.grp,"getgrnam",side_effect=lambda name:groups[name]):
            with self.assertRaises(PermissionError):
                observer_runtime.preflight(issuer_dir=Path(td),observer_dir=Path(td),
                                           state_dir=Path(td))


if __name__ == "__main__":
    unittest.main()
